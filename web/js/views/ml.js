// «Качество модели» — отчётность по работе модели: состояние ML-сервиса, каскад решения, качество (кривые, матрицы ошибок,
// ложные срабатывания по типам абонентов) и вклад ML относительно линейной стадии.
// Качество берётся из отчёта обучения (report.json рядом с моделью), живые показатели — из ядра и ML-сервиса.

import { ApiError, getMLReport, getMLService, getStatus } from '../api.js';
import { histogram, xy } from '../charts.js';
import { icon } from '../icons.js';
import { FRAUD_KINDS, LEGIT_KINDS, factorName, kindName } from '../labels.js';
import { fmt, h, hbars, tile, widget } from '../ui.js';

const C = { ml: 'var(--c-info)', s1: 'var(--c-muted)', legit: 'var(--c-good)', fraud: 'var(--c-block)', review: 'var(--c-review)', block: 'var(--c-block)' };
const pct = (x, d = 1) => fmt.pct(x, d);
const fpr = (x) => fmt.pct(x, x < 0.001 ? 4 : 2);

/** Необязательный источник: ошибка → null, чтобы раздел показывал остальное. */
async function optional(p) {
  try { return await p; } catch (e) { if (e instanceof ApiError && e.status === 401) throw e; return null; }
}

export async function render(root) {
  const [status, report, service] = await Promise.all([getStatus(), optional(getMLReport()), optional(getMLService())]);
  const ml = status.engine.ml;
  const parts = [liveRow(status, ml, service)];

  if (!ml.enabled) {
    root.replaceChildren(...parts, widget('ML-сервис не подключён', h('div', { class: 'empty' }, 'Не задан ML_URL — решения принимает линейная стадия.')));
    return;
  }
  parts.push(cascade(ml, report));
  if (!report) {
    parts.push(widget('Отчёт об обучении', h('div', { class: 'empty' }, 'У текущей модели нет report.json. Переобучите: scripts/retrain.sh.')));
    root.replaceChildren(...parts);
    return;
  }
  parts.push(dataBanner(report), qualityRow(report), curves(report), confusions(report), kinds(report), graphSection(report), tail(report, status));
  root.replaceChildren(...parts);
}

// ---- живое состояние ----

function liveRow(status, ml, service) {
  const t = status.totals;
  const lat = service && service.latency_ms;
  const state = !ml.enabled ? ['не подключён', ''] : ml.breaker_open ? ['отказ', 'high'] : ml.active ? ['работает', 'ok'] : ['ожидание', 'warn'];
  const sent = t.ml_calls || 0;
  const all = t.ml + t.linear;
  // ml и linear — из телеметрии (переживают перезапуск); остальное считают процессы с момента запуска
  return h('div', { class: 'grid cols-6' },
    tile('ML-сервис', state[0], ml.version || '—', state[1]),
    tile('Через ML', fmt.int(t.ml), `${pct(all ? t.ml / all : 0, 1)} из ${fmt.int(all)} решений`, 'info'),
    tile('Ошибки ML', fmt.int(t.ml_errors || 0), `${fmt.int(sent)} запросов с запуска ядра`, t.ml_errors ? 'warn' : 'ok'),
    tile('Откаты (breaker)', fmt.int(t.ml_skipped || 0), 'с запуска ядра', t.ml_skipped ? 'warn' : ''),
    tile('Инференс p50 / p95', lat ? `${fmt.num(lat.p50, 1)} / ${fmt.num(lat.p95, 1)}` : '—', lat ? `мс, p99 ${fmt.num(lat.p99, 1)}` : 'нет замеров', lat && lat.p95 > 30 ? 'warn' : ''),
    tile('Запросов в сервисе', service ? fmt.int(service.requests) : '—', service ? `работает ${fmt.uptime(service.uptime_sec)}` : 'нет данных'));
}

// ---- каскад решения ----

function cascade(ml, report) {
  const th = ml.thresholds || (report && report.model.thresholds) || {};
  const gate = ml.gate ?? th.gate;
  const box = (title, text, cls = '') => h('div', { class: 'flow-box ' + cls }, h('b', {}, title), h('div', { class: 'muted' }, text));
  const arrow = h('div', { class: 'flow-arrow' }, icon('arrow'));
  return widget('Каскад решения', h('div', { class: 'flow' },
    box('Вызов', 'метаданные сигнализации'),
    arrow,
    box('Защита', 'экстренные 112/101/102/103/104 — всегда «пропуск»'),
    arrow,
    box('Стадия 1', `линейная модель, ворота ${fmt.num(gate, 4)}`),
    arrow,
    box('Стадия 2 — ML', `CatBoost + SHAP${report ? `, ~${pct(report.quality.ml_traffic_share, 0)} трафика` : ''}`, 'ml'),
    arrow,
    box('Политика', `проверка ≥ ${fmt.num(th.review, 4)}, блок ≥ ${fmt.num(th.block, 4)} и ${th.min_signals || 2}+ сигнала`, 'rule')),
  { sub: '«проверка» — вызов проходит и уходит аналитику' });
}

// ---- данные и качество ----

function dataBanner(r) {
  const d = r.data, m = r.model;
  return h('div', { class: 'note' },
    h('b', {}, d.synthetic ? 'Синтетические данные. ' : 'Размеченные данные. '),
    `${m.version}, обучена ${fmt.dateTime(m.trained_at)}. Выборки: обучение ${fmt.int(d.train)}, калибровка ${fmt.int(d.calib)}, проверка ${fmt.int(d.test)} (мошенничество ${pct(d.test_fraud_share, 1)}).`);
}

function qualityRow(r) {
  const q = r.quality, t = r.targets;
  const okR = q.review.fpr <= t.review_fpr * 1.05, okB = q.block.fpr <= t.block_fpr * 1.5;
  return h('div', { class: 'grid cols-6', style: 'margin-top:14px' },
    tile('ROC-AUC', fmt.num(q.auc, 4), '', 'info'),
    tile('PR-AUC', fmt.num(q.pr_auc, 4), '', 'info'),
    tile('Проверка: поймано', pct(q.review.recall), `${fmt.int(q.review.tp)} из ${fmt.int(q.review.tp + q.review.fn)}`),
    tile('Проверка: ложных', fpr(q.review.fpr), `цель ≤ ${fpr(t.review_fpr)}, ${fmt.int(q.review.fp)} шт.`, okR ? 'ok' : 'warn'),
    tile('Блок: поймано', pct(q.block.recall), `${fmt.int(q.block.tp)} из ${fmt.int(q.block.tp + q.block.fn)}`),
    tile('Блок: ложных', fpr(q.block.fpr), `цель ≤ ${fpr(t.block_fpr)}, ${fmt.int(q.block.fp)} из ${fmt.int(r.data.test_legit)}`, okB ? 'ok' : 'high'));
}

function curves(r) {
  const c = r.curves, th = r.model.thresholds, t = r.targets, q = r.quality, u = r.uplift;
  const logTicks = [1e-5, 1e-4, 1e-3, 1e-2, 1e-1, 1];
  const roc = widget('Полнота и ложные срабатывания', xy([
    { label: 'ML', color: C.ml, x: c.roc_ml.fpr, y: c.roc_ml.recall },
    { label: 'стадия 1', color: C.s1, x: c.roc_stage1.fpr, y: c.roc_stage1.recall, dash: '5 3' },
  ], {
    logX: true, xMin: 1e-5, xMax: 1, xTicks: logTicks, xFmt: (v) => fmt.pct(v, 3), yFmt: (v) => fmt.pct(v, 0), xLabel: 'доля ложных срабатываний', yLabel: 'доля пойманных',
    vlines: [{ x: t.review_fpr, label: `цель «проверки» ${fmt.pct(t.review_fpr, 2)}`, color: C.review }, { x: t.block_fpr, label: `цель «блока» ${fmt.pct(t.block_fpr, 3)}`, color: C.block }],
    marks: [{ x: Math.max(q.review.fpr, 1e-5), y: q.review.recall, label: `«проверка»: ${pct(q.review.recall)} при ${fpr(q.review.fpr)}`, color: C.review },
      { x: Math.max(q.block.fpr, 1e-5), y: q.block.recall, label: `«блок»: ${pct(q.block.recall)} при ${fpr(q.block.fpr)}`, color: C.block }],
  }));

  const pr = widget('Точность и полнота', xy([{ label: 'ML', color: C.ml, x: c.pr_ml.recall, y: c.pr_ml.precision, area: true }],
    { xMin: 0, xMax: 1, xFmt: (v) => fmt.pct(v, 0), yFmt: (v) => fmt.pct(v, 0), xLabel: 'полнота', yLabel: 'точность' }),
  { sub: `мошенничества ${pct(r.data.test_fraud_share, 0)}` });

  const dist = widget('Распределение score', histogram(c.score_hist.edges, [
    { label: 'легитимные', color: C.legit, values: c.score_hist.legit }, { label: 'мошеннические', color: C.fraud, values: c.score_hist.fraud }],
  { vlines: [{ x: th.review, label: `«проверка» ${fmt.num(th.review, 4)}`, color: C.review }, { x: th.block, label: `«блок» ${fmt.num(th.block, 4)}`, color: C.block }], xFmt: (v) => fmt.num(v, 5) }));

  const sw = c.sweep;
  const sweep = widget('Эффект порога', xy([
    { label: 'пойманные', color: C.ml, x: sw.threshold, y: sw.recall },
    { label: 'ложные', color: C.fraud, x: sw.threshold, y: sw.fpr },
  ], { logX: true, xMin: 1e-4, xMax: 1, xTicks: [1e-4, 1e-3, 1e-2, 1e-1, 1], xFmt: (v) => fmt.num(v, 4), yFmt: (v) => fmt.pct(v, 0), xLabel: 'порог score',
    vlines: [{ x: th.review, label: '«проверка»', color: C.review }, { x: th.block, label: '«блок»', color: C.block }] }));

  const cal = widget('Калибровка', xy([
    { label: 'фактическая доля', color: C.ml, x: c.calibration.map((p) => p.predicted), y: c.calibration.map((p) => p.observed), dots: true, n: c.calibration.map((p) => p.n) },
  ], { logX: true, logY: true, xMin: 1e-5, xMax: 1, yMin: 1e-5, yMax: 1, xTicks: logTicks, yTicks: logTicks, xFmt: (v) => fmt.num(v, 5), yFmt: (v) => fmt.num(v, 5),
    xLabel: 'предсказанный score', yLabel: 'фактическая доля', diagonal: true }),
  { sub: `при доле мошенничества ${pct(r.model.prevalence, 1)}` });

  const row = (label, x) => [
    { name: label + ' ст.1', label: 'Стадия 1 · ' + label, value: x.stage1, color: C.s1, text: pct(x.stage1) },
    { name: label + ' ML', label: 'ML · ' + label, value: x.ml, color: C.ml, text: pct(x.ml) },
  ];
  const uplift = widget('Что даёт ML', h('div', {},
    hbars([...row(fmt.pct(u.recall_at_review_fpr.fpr, 2), u.recall_at_review_fpr), ...row(fmt.pct(u.recall_at_block_fpr.fpr, 3), u.recall_at_block_fpr)], { max: 1, valWidth: 56 }),
    h('div', { class: 'muted', style: 'font-size:12px;margin-top:8px' }, `AUC: ${fmt.num(u.auc_stage1, 4)} → ${fmt.num(u.auc_ml, 4)}`)),
  { sub: 'пойманные при доле ложных' });

  return h('div', { class: 'grid cols-3', style: 'margin-top:14px' }, roc, pr, dist, sweep, cal, uplift);
}

function matrix(title, c, sub) {
  const cell = (label, n, tone) => h('div', { class: 'cm ' + tone }, h('div', { class: 'cm-n' }, fmt.int(n)), h('div', { class: 'cm-l' }, label));
  return widget(title, h('div', {},
    h('div', { class: 'cm-grid' },
      h('div', { class: 'cm-h' }, ''), h('div', { class: 'cm-h' }, 'помечено'), h('div', { class: 'cm-h' }, 'пропущено'),
      h('div', { class: 'cm-h side' }, 'мошенники'), cell('поймано', c.tp, 'good'), cell('пропущено', c.fn, 'bad'),
      h('div', { class: 'cm-h side' }, 'нормальные'), cell('ложно', c.fp, 'bad'), cell('верно', c.tn, 'good')),
    h('div', { class: 'muted', style: 'font-size:12px;margin-top:8px' }, `точность ${pct(c.precision)} · полнота ${pct(c.recall)} · ложных ${fpr(c.fpr)}`)), { sub });
}

function confusions(r) {
  const q = r.quality;
  const prec = h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Доля мошенничества'), h('th', { class: 'num' }, 'Проверка'), h('th', { class: 'num' }, 'Блок'))),
    h('tbody', {}, q.precision_by_prevalence.map((p) => h('tr', {}, h('td', {}, pct(p.prevalence, 1)), h('td', { class: 'num' }, pct(p.review)), h('td', { class: 'num' }, pct(p.block))))));
  return h('div', { class: 'grid cols-3', style: 'margin-top:14px' },
    matrix('Ошибки: проверка', q.review, 'вердикт ≥ проверка'),
    matrix('Ошибки: блок', q.block, 'вердикт = блок'),
    widget('Точность в реальном потоке', h('div', { class: 'table-wrap' }, prec), { sub: 'при тех же полноте и ложных', flush: true }));
}

function kinds(r) {
  const legit = LEGIT_KINDS.filter((k) => r.by_kind[k]).map((k) => ({ k, ...r.by_kind[k] }));
  const fraud = FRAUD_KINDS.filter((k) => r.by_kind[k]).map((k) => ({ k, ...r.by_kind[k] }));
  const fp = widget('Ложные срабатывания по абонентам', hbars(legit.map((x) => ({ name: x.k, label: kindName(x.k), value: x.review / x.n,
    text: `${pct(x.review / x.n, 2)}${x.block ? ` · блок ${x.block}` : ''}`, color: x.review / x.n > 0.05 ? C.block : C.review })),
  { max: Math.max(...legit.map((x) => x.review / x.n), 0.02), valWidth: 110 }), { sub: 'доля «проверка» и «блок»' });
  const det = widget('Обнаружение по типам мошенничества', hbars(fraud.map((x) => ({ name: x.k, label: kindName(x.k), value: x.review / x.n,
    text: `${pct(x.review / x.n)} · блок ${pct(x.block / x.n, 0)}`, color: C.ml })), { max: 1, valWidth: 130 }), { sub: 'доля «проверка» и «блок»' });
  return h('div', { class: 'grid cols-2', style: 'margin-top:14px' }, fp, det);
}

// ---- графовый анализ (NetworkX, ADR-0018): структура сети обучающего набора и сверка с онлайн-эвристикой Go ----

function graphSection(r) {
  const g = r.graph;
  if (!g || !g.available) {
    return widget('Графовый анализ связей (NetworkX)', h('div', { class: 'empty' }, (g && g.reason) || 'недоступен (старая модель без графового раздела — переобучите)'));
  }
  const s = g.summary, fv = g.fan_validation;
  const summary = widget('Структура сети вызовов', h('dl', { class: 'kv' },
    h('dt', {}, 'Вершин (номеров)'), h('dd', {}, fmt.int(s.nodes)),
    h('dt', {}, 'Рёбер (вызовов)'), h('dd', {}, fmt.int(s.edges)),
    h('dt', {}, 'Компонент связности'), h('dd', {}, fmt.int(s.components)),
    h('dt', {}, 'Крупнейшая компонента'), h('dd', {}, `${fmt.int(s.largest_component)} номеров`),
    h('dt', {}, 'Сообществ (modularity)'), h('dd', {}, s.communities != null ? `${fmt.int(s.communities)} (${fmt.num(s.modularity, 3)})` : '—'),
    h('dt', {}, 'Степень среди вызывающих'), h('dd', {}, `медиана ${fmt.num(s.out_degree_p50, 1)}, p99 ${fmt.num(s.out_degree_p99, 1)}`)),
  { sub: 'офлайн, весь набор обучения' });

  let body = h('div', { class: 'empty' }, 'Нет данных для сверки (в наборе нет r_fan_member).');
  if (fv && fv.available) {
    body = h('div', {},
      h('div', { class: 'grid cols-3' },
        tile('Нашёл граф', fmt.int(fv.networkx_fans), 'независимый анализ, весь набор'),
        tile('Нашёл Go', fmt.int(fv.go_fans), 'онлайн, скользящее окно'),
        tile('Совпадение', fv.agreement_rate != null ? pct(fv.agreement_rate) : '—', `${fmt.int(fv.agree)} общих номеров`, fv.agreement_rate > 0.5 ? 'ok' : 'warn')),
      h('div', { class: 'muted', style: 'font-size:12px;margin-top:10px' },
        `только у Go: ${fmt.int(fv.only_go)} · только у графа (окно не уместило): ${fmt.int(fv.only_networkx)}` +
        (fv.capped ? ` · кандидатов ограничено до ${fmt.int(fv.candidates)}` : '')));
  }
  const validation = widget('Сверка с онлайн-эвристикой Go', body, { sub: 'расхождение — честная граница окна, не ошибка' });
  return h('div', { class: 'grid cols-2', style: 'margin-top:14px' }, summary, validation);
}

function tail(r, status) {
  const c = r.quality.callers, q = r.quality;
  const live = status.totals;
  const liveMl = live.linear + live.ml ? live.ml / (live.linear + live.ml) : null;
  const imp = Object.entries(r.importances).slice(0, 14).map(([name, v]) => ({ name, label: factorName(name), title: name, value: v, text: fmt.num(v, 1) }));
  return h('div', { class: 'grid cols-3', style: 'margin-top:14px' },
    widget('Важность признаков', hbars(imp, { color: C.ml }), { sub: `топ-14 из ${r.model.features.length}`, cls: 'span-2' }),
    widget('Каскад и реакция', h('dl', { class: 'kv' },
      h('dt', {}, 'В ML: обучение'), h('dd', {}, `${pct(q.ml_traffic_share)} (легитимных ${pct(q.ml_traffic_share_legit)})`),
      h('dt', {}, 'В ML: сейчас'), h('dd', {}, liveMl === null ? '—' : pct(liveMl)),
      h('dt', {}, 'Пол-правило'), h('dd', {}, `${fmt.int(q.rule_floor.legit)} легитимных, ${fmt.int(q.rule_floor.fraud)} мошеннических`),
      h('dt', {}, 'Экстренные'), h('dd', {}, `${fmt.int(q.emergency.n)}, блокировок ${fmt.int(q.emergency.blocked)}`),
      h('dt', {}, 'Номера-нарушители'), h('dd', {}, fmt.int(c.fraud_callers)),
      h('dt', {}, 'До «проверки»'), h('dd', {}, `${pct(c.reviewed / Math.max(c.fraud_callers, 1), 0)}, медиана ${c.median_calls_to_review ?? '—'} вызова`),
      h('dt', {}, 'До «блока»'), h('dd', {}, `${pct(c.blocked / Math.max(c.fraud_callers, 1), 0)}, медиана ${c.median_calls_to_block ?? '—'} вызова`),
      h('dt', {}, 'Калибровка'), h('dd', { class: 'mono' }, `logit·${fmt.num(r.model.platt.a, 3)} ${fmt.signed(r.model.platt.b, 3)}`))));
}
