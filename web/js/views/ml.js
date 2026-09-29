// «ML-модель» — полная отчётность по работе модели: как устроен каскад, насколько модель точна (кривые, матрицы ошибок,
// ложные срабатывания по типам абонентов), чем она лучше линейной стадии и что происходит с ней прямо сейчас.
// Данные качества берутся из отчёта обучения (report.json рядом с моделью), живые — из ядра и ML-сервиса.

import { ApiError, getMLReport, getMLService, getStatus } from '../api.js';
import { histogram, xy } from '../charts.js';
import { FRAUD_KINDS, LEGIT_KINDS, factorName, kindName } from '../labels.js';
import { fmt, h, hbars, tile, widget } from '../ui.js';

const C = { ml: '#3f8cff', s1: '#9aa4b2', legit: '#59db8f', fraud: '#e45959', review: '#ffa059', block: '#e45959' };
const pct = (x, d = 1) => fmt.pct(x, d);
const fpr = (x) => fmt.pct(x, x < 0.001 ? 4 : 2);

/** Загружает необязательный источник: ошибка → null, чтобы раздел показывал остальное. */
async function optional(p) {
  try { return await p; } catch (e) { if (e instanceof ApiError && e.status === 401) throw e; return null; }
}

export async function render(root) {
  const [status, report, service] = await Promise.all([getStatus(), optional(getMLReport()), optional(getMLService())]);
  const ml = status.engine.ml;
  const parts = [liveRow(status, ml, service)];

  if (!ml.enabled) {
    root.replaceChildren(...parts, widget('ML-сервис не подключён', h('div', { class: 'empty' }, 'В настройках ядра не задан ML_URL: решения принимает только линейная стадия. Подключите сервис (профиль compose «ml»), и здесь появится отчётность по модели.')));
    return;
  }
  parts.push(cascadeDiagram(status, ml, report));
  if (!report) {
    parts.push(widget('Отчёт об обучении недоступен', h('div', { class: 'empty' },
      'У текущей модели нет отчёта об обучении (report.json) или ML-сервис не отвечает. Переобучите модель — scripts/retrain.sh — и загрузите её вместе с отчётом.')));
    root.replaceChildren(...parts);
    return;
  }
  parts.push(dataBanner(report), qualityRow(report), curves(report), uplift(report), confusions(report), kinds(report), tail(report, status));
  root.replaceChildren(...parts);
}

// ---- живое состояние ----

function liveRow(status, ml, service) {
  const t = status.totals;
  const lat = service && service.latency_ms;
  const state = !ml.enabled ? ['не подключён', ''] : ml.breaker_open ? ['отказ: работает откат на линейную стадию', 'high'] : ml.active ? ['работает', 'ok'] : ['ожидание модели', 'warn'];
  const sent = t.ml_calls || 0;
  // ml, linear — из телеметрии: переживают перезапуск. Остальные счётчики считает процесс ядра и сервис ML с момента запуска.
  const since = `с запуска ядра (${fmt.uptime(status.service.uptime_sec)})`;
  return h('div', { class: 'grid cols-6' },
    tile('ML-сервис', state[0], ml.version || '—', state[1]),
    tile('Решений через ML', fmt.int(t.ml), `из ${fmt.int(t.ml + t.linear)} всего (${pct(t.ml + t.linear ? t.ml / (t.ml + t.linear) : 0, 1)}), с учётом перезапусков`, 'info'),
    tile('Ошибки ML', fmt.int(t.ml_errors || 0), sent ? `${pct((t.ml_errors || 0) / sent, 2)} из ${fmt.int(sent)} запросов ${since}` : `запросов к ML ${since}: 0`, t.ml_errors ? 'warn' : 'ok'),
    tile('Пропущено (breaker)', fmt.int(t.ml_skipped || 0), `вызовы ушли на линейную стадию ${since}`, t.ml_skipped ? 'warn' : ''),
    tile('Инференс p50 / p95', lat ? `${fmt.num(lat.p50, 1)} / ${fmt.num(lat.p95, 1)}` : '—', lat ? `мс · p99 ${fmt.num(lat.p99, 1)}, max ${fmt.num(lat.max, 1)}` : 'замеров с запуска ML-сервиса ещё нет', lat && lat.p95 > 30 ? 'warn' : 'ok'),
    tile('Запросов в сервисе', service ? fmt.int(service.requests) : '—', service ? `ошибок ${fmt.int(service.errors)}, ML-сервис работает ${fmt.uptime(service.uptime_sec)}` : 'нет данных'));
}

// ---- как устроен каскад ----

function cascadeDiagram(status, ml, report) {
  const th = ml.thresholds || (report && report.model.thresholds) || {};
  const gate = ml.gate ?? th.gate;
  const box = (title, text, tone = '') => h('div', { class: 'flow-box ' + tone }, h('b', {}, title), h('div', { class: 'muted' }, text));
  const arrow = h('div', { class: 'flow-arrow' }, '→');
  const share = report ? pct(report.quality.ml_traffic_share, 0) : null;
  return widget('Как принимается решение', h('div', {},
    h('div', { class: 'flow' },
      box('1. Вызов', 'метаданные сигнализации: номера, время, длительность, вход, тип соединения'),
      arrow,
      box('2. Защитный слой', 'экстренные 112/101/102/103/104 — всегда «пропуск», до всякого скоринга', 'ok'),
      arrow,
      box('3. Стадия 1: линейная модель', `26 признаков, вклад каждого точный. ~2,5 мкс. Ниже порога ${fmt.num(gate, 4)} и без сильного сигнала — вызов не идёт в ML`),
      arrow,
      box('4. Стадия 2: ML (CatBoost)', `серая зона и подозрительные вызовы${share ? ` (~${share} трафика в обучающей выборке)` : ''}. Score + вклады признаков (SHAP), ~8 мс, таймаут 50 мс`, 'info'),
      arrow,
      box('5. Политика', `проверка: score ≥ ${fmt.num(th.review, 4)}; блок: score ≥ ${fmt.num(th.block, 4)} и ≥ ${th.min_signals || 2} сильных сигнала. Подмена и номер вне диапазонов — не ниже «проверки»`, 'avg')),
    h('p', { class: 'muted', style: 'margin:10px 0 0;font-size:12px' },
      'ML не «проверяет» вызов после решения — он входит в само решение. Если ML недоступен (таймаут, ошибка, breaker), вердикт даёт линейная стадия, а экстренные службы по-прежнему проходят без ограничений. ' +
      '«Проверка» — вердикт для аналитика: вызов проходит, но попадает в список «Проблемы» с разбором причин.')));
}

// ---- данные и качество ----

function dataBanner(r) {
  const d = r.data, m = r.model;
  return h('div', { class: 'note ' + (d.synthetic ? 'warn' : 'ok') },
    h('b', {}, d.synthetic ? 'Данные обучения синтетические. ' : 'Обучено на размеченных данных. '),
    d.synthetic ? 'Показатели ниже описывают работу модели на модельном трафике: на реальной сети цифры будут другими, метод оценки — тот же. ' : '',
    `Модель ${m.version}, обучена ${fmt.dateTime(m.trained_at)}. Выборки: обучение ${fmt.int(d.train)}, калибровка и пороги ${fmt.int(d.calib)}, независимая проверка ${fmt.int(d.test)} ` +
    `(мошеннических ${pct(d.test_fraud_share, 1)}). Источник: ${d.source}.`);
}

function qualityRow(r) {
  const q = r.quality, t = r.targets;
  const okR = q.review.fpr <= t.review_fpr * 1.05, okB = q.block.fpr <= t.block_fpr * 1.5;
  return h('div', { class: 'grid cols-6', style: 'margin-top:14px' },
    tile('ROC-AUC', fmt.num(q.auc, 4), 'способность отличать мошенничество', 'info'),
    tile('PR-AUC', fmt.num(q.pr_auc, 4), 'точность при разной полноте', 'info'),
    tile('Проверка: поймано', pct(q.review.recall), `${fmt.int(q.review.tp)} из ${fmt.int(q.review.tp + q.review.fn)} мошеннических`, 'ok'),
    tile('Проверка: ложных', fpr(q.review.fpr), `цель ≤ ${fpr(t.review_fpr)} · ${fmt.int(q.review.fp)} легитимных`, okR ? 'ok' : 'warn'),
    tile('Блок: поймано', pct(q.block.recall), `${fmt.int(q.block.tp)} из ${fmt.int(q.block.tp + q.block.fn)}`, 'ok'),
    tile('Блок: ложных', fpr(q.block.fpr), `цель ≤ ${fpr(t.block_fpr)} · ${fmt.int(q.block.fp)} из ${fmt.int(r.data.test_legit)}`, okB ? 'ok' : 'high'));
}

function curves(r) {
  const c = r.curves, th = r.model.thresholds, t = r.targets, q = r.quality;
  const logTicks = [1e-5, 1e-4, 1e-3, 1e-2, 1e-1, 1];
  const roc = widget('Полнота против ложных срабатываний', xy([
    { label: 'ML (стадия 2)', color: C.ml, x: c.roc_ml.fpr, y: c.roc_ml.recall },
    { label: 'линейная стадия 1', color: C.s1, x: c.roc_stage1.fpr, y: c.roc_stage1.recall, dash: '5 3' },
  ], {
    logX: true, xMin: 1e-5, xMax: 1, xTicks: logTicks, xFmt: (v) => fmt.pct(v, 3), yFmt: (v) => fmt.pct(v, 0), xLabel: 'доля ложных срабатываний (логарифмическая шкала)', yLabel: 'доля пойманных',
    vlines: [{ x: t.review_fpr, label: `цель для «проверки» ${fmt.pct(t.review_fpr, 2)}`, color: C.review }, { x: t.block_fpr, label: `цель для «блока» ${fmt.pct(t.block_fpr, 3)}`, color: C.block }],
    marks: [{ x: Math.max(q.review.fpr, 1e-5), y: q.review.recall, label: `рабочая точка «проверка»: ${pct(q.review.recall)} при ${fpr(q.review.fpr)}`, color: C.review },
      { x: Math.max(q.block.fpr, 1e-5), y: q.block.recall, label: `рабочая точка «блок»: ${pct(q.block.recall)} при ${fpr(q.block.fpr)}`, color: C.block }],
  }), { sub: 'чем выше и левее, тем лучше' });

  const pr = widget('Точность против полноты', xy([{ label: 'ML', color: C.ml, x: c.pr_ml.recall, y: c.pr_ml.precision, area: true }],
    { xMin: 0, xMax: 1, xFmt: (v) => fmt.pct(v, 0), yFmt: (v) => fmt.pct(v, 0), xLabel: 'полнота (доля пойманных)', yLabel: 'точность (доля верных среди помеченных)', yMin: 0, yMax: 1 }),
  { sub: `на проверочной выборке (${pct(r.data.test_fraud_share, 0)} мошеннических)` });

  const dist = widget('Распределение score', histogram(c.score_hist.edges, [
    { label: 'легитимные', color: C.legit, values: c.score_hist.legit }, { label: 'мошеннические', color: C.fraud, values: c.score_hist.fraud }],
  { vlines: [{ x: th.review, label: `порог «проверка» ${fmt.num(th.review, 4)}`, color: C.review }, { x: th.block, label: `порог «блок» ${fmt.num(th.block, 4)}`, color: C.block }], xFmt: (v) => fmt.num(v, 5) }),
  { sub: 'чем дальше классы друг от друга, тем лучше модель' });

  const sw = c.sweep;
  const sweep = widget('Что даёт каждый порог', xy([
    { label: 'доля пойманных', color: C.ml, x: sw.threshold, y: sw.recall },
    { label: 'доля ложных срабатываний', color: C.fraud, x: sw.threshold, y: sw.fpr },
  ], { logX: true, xMin: 1e-4, xMax: 1, xTicks: [1e-4, 1e-3, 1e-2, 1e-1, 1], xFmt: (v) => fmt.num(v, 4), yFmt: (v) => fmt.pct(v, 0), xLabel: 'порог score',
    vlines: [{ x: th.review, label: 'порог «проверка»', color: C.review }, { x: th.block, label: 'порог «блок»', color: C.block }] }),
  { sub: 'порог выбран под целевую долю ложных срабатываний' });

  const cal = widget('Калибровка: насколько score похож на вероятность', xy([
    { label: 'наблюдаемая доля мошенничества', color: C.ml, x: c.calibration.map((p) => p.predicted), y: c.calibration.map((p) => p.observed), dots: true, n: c.calibration.map((p) => p.n) },
  ], { logX: true, logY: true, xMin: 1e-5, xMax: 1, yMin: 1e-5, yMax: 1, xTicks: logTicks, yTicks: logTicks, xFmt: (v) => fmt.num(v, 5), yFmt: (v) => fmt.num(v, 5),
    xLabel: 'предсказанный score', yLabel: 'фактическая доля', diagonal: true }),
  { sub: `приведено к доле мошенничества ${pct(r.model.prevalence, 1)} в боевом потоке` });

  return h('div', { class: 'grid cols-3', style: 'margin-top:14px' }, roc, pr, dist, sweep, cal,
    widget('Как читать', h('div', { class: 'muted', style: 'line-height:1.5' },
      h('p', { style: 'margin-top:0' }, h('b', {}, 'Полнота'), ' — какая часть мошеннических вызовов поймана. ', h('b', {}, 'Ложные срабатывания'), ' — какая часть нормальных вызовов отмечена зря; для кейса это главный показатель.'),
      h('p', {}, 'Порог «проверка» подобран так, чтобы ложных было не больше ', fmt.pct(t.review_fpr, 2), ', порог «блок» — не больше ', fmt.pct(t.block_fpr, 3), ' плюс требование двух независимых сильных сигналов.'),
      h('p', { style: 'margin-bottom:0' }, 'Если кривые «дальше» линейной стадии — ML действительно добавляет качество, а не повторяет её.'))));
}

function uplift(r) {
  const u = r.uplift;
  const row = (title, x) => [
    { name: title + ' — стадия 1', label: title + ': линейная стадия', value: x.stage1, color: C.s1, text: pct(x.stage1) },
    { name: title + ' — ML', label: title + ': ML', value: x.ml, color: C.ml, text: pct(x.ml) },
  ];
  return h('div', { class: 'grid cols-3', style: 'margin-top:14px' },
    widget('Что добавляет ML к линейной стадии', h('div', {},
      h('div', { class: 'muted', style: 'font-size:12px;margin-bottom:6px' }, `Доля пойманных мошеннических при допустимой доле ложных ${fmt.pct(u.recall_at_review_fpr.fpr, 2)} («проверка»)`),
      hbars(row('при ' + fmt.pct(u.recall_at_review_fpr.fpr, 2), u.recall_at_review_fpr), { max: 1 }),
      h('div', { class: 'muted', style: 'font-size:12px;margin:12px 0 6px' }, `…и при ${fmt.pct(u.recall_at_block_fpr.fpr, 3)} («блок»)`),
      hbars(row('при ' + fmt.pct(u.recall_at_block_fpr.fpr, 3), u.recall_at_block_fpr), { max: 1 }),
      h('div', { class: 'muted', style: 'font-size:12px;margin-top:10px' }, `ROC-AUC: линейная ${fmt.num(u.auc_stage1, 4)} → ML ${fmt.num(u.auc_ml, 4)}`)),
    { cls: 'span-2', sub: 'на одной и той же проверочной выборке' }),
    widget('Поведение каскада', h('dl', { class: 'kv' },
      h('dt', {}, 'Трафик в ML'), h('dd', {}, `${pct(r.quality.ml_traffic_share)} всего, ${pct(r.quality.ml_traffic_share_legit)} легитимного`),
      h('dt', {}, 'Без ворот'), h('dd', {}, `проверка ${pct(r.quality.flat_review.recall)}, блок ${pct(r.quality.flat_block.recall)} — ворота стоят ${fmt.num((r.quality.flat_review.recall - r.quality.review.recall) * 100, 2)} п.п. полноты и снимают нагрузку с ML`),
      h('dt', {}, 'Пол-правило'), h('dd', {}, `подняло до «проверки» ${fmt.int(r.quality.rule_floor.legit)} легитимных и ${fmt.int(r.quality.rule_floor.fraud)} мошеннических (модель молчала)`),
      h('dt', {}, 'Экстренные'), h('dd', {}, `${fmt.int(r.quality.emergency.n)} вызовов, пропущено ${fmt.int(r.quality.emergency.allowed)}, заблокировано ${fmt.int(r.quality.emergency.blocked)}`))));
}

function matrix(title, c, sub) {
  const cell = (label, n, tone, hint) => h('div', { class: 'cm ' + tone }, h('div', { class: 'cm-n' }, fmt.int(n)), h('div', { class: 'cm-l' }, label), h('div', { class: 'muted', style: 'font-size:11px' }, hint));
  return widget(title, h('div', {},
    h('div', { class: 'cm-grid' },
      h('div', { class: 'cm-h' }, ''), h('div', { class: 'cm-h' }, 'помечено'), h('div', { class: 'cm-h' }, 'пропущено'),
      h('div', { class: 'cm-h side' }, 'мошенничество'), cell('поймано', c.tp, 'good', 'верно'), cell('пропущено', c.fn, 'bad', 'ошибка'),
      h('div', { class: 'cm-h side' }, 'нормальные'), cell('помечено зря', c.fp, 'bad', 'ложное срабатывание'), cell('пропущено', c.tn, 'good', 'верно')),
    h('div', { class: 'muted', style: 'font-size:12px;margin-top:8px' }, `Точность ${pct(c.precision)} (на этой выборке, где мошенничества много) · полнота ${pct(c.recall)} · ложных ${fpr(c.fpr)}`)), { sub });
}

function confusions(r) {
  const q = r.quality;
  const prec = h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Доля мошенничества в потоке'), h('th', { class: 'num' }, 'Точность «проверки»'), h('th', { class: 'num' }, 'Точность «блока»'))),
    h('tbody', {}, q.precision_by_prevalence.map((p) => h('tr', {}, h('td', {}, pct(p.prevalence, 1)), h('td', { class: 'num' }, pct(p.review)), h('td', { class: 'num' }, pct(p.block))))));
  return h('div', { class: 'grid cols-3', style: 'margin-top:14px' },
    matrix('Матрица ошибок: «проверка»', q.review, 'вердикт ≥ проверка'),
    matrix('Матрица ошибок: «блок»', q.block, 'вердикт = блок'),
    widget('Точность зависит от потока', h('div', {}, h('div', { class: 'table-wrap' }, prec),
      h('p', { class: 'muted', style: 'font-size:12px;margin-bottom:0' }, 'В реальной сети мошенничества меньше, чем в проверочной выборке, поэтому точность считается при тех же полноте и ложных срабатываниях для разной доли мошенничества.'))));
}

function kinds(r) {
  const legit = LEGIT_KINDS.filter((k) => r.by_kind[k]).map((k) => ({ k, ...r.by_kind[k] }));
  const fraud = FRAUD_KINDS.filter((k) => r.by_kind[k]).map((k) => ({ k, ...r.by_kind[k] }));
  const fp = widget('Ложные срабатывания по типам абонентов', legit.length ? h('div', {},
    hbars(legit.map((x) => ({ name: x.k, label: kindName(x.k), value: x.review / x.n, text: `${pct(x.review / x.n, 2)}${x.block ? ` · блок ${x.block}` : ''}`, color: x.review / x.n > 0.05 ? C.block : C.review })), { max: Math.max(...legit.map((x) => x.review / x.n), 0.02), valWidth: 110 }),
    h('p', { class: 'muted', style: 'font-size:12px;margin:8px 0 0' }, 'Доля нормальных вызовов группы, получивших «проверку» или «блок». Колл-центры, банки и корпоративные мультисим — самые трудные для любой модели: ведут себя как мошенники по метаданным.')) : h('div', { class: 'empty' }, 'нет данных'), { sub: 'главный риск кейса' });
  const det = widget('Обнаружение по типам мошенничества', fraud.length ? h('div', {},
    hbars(fraud.map((x) => ({ name: x.k, label: kindName(x.k), value: x.review / x.n, text: `${pct(x.review / x.n)} · блок ${pct(x.block / x.n, 0)}`, color: C.ml })), { max: 1, valWidth: 130 }),
    h('p', { class: 'muted', style: 'font-size:12px;margin:8px 0 0' }, 'Доля вызовов типа, попавших в «проверку» или «блок» (блок — отдельно).')) : h('div', { class: 'empty' }, 'нет данных'), { sub: 'полнота по сценариям' });
  return h('div', { class: 'grid cols-2', style: 'margin-top:14px' }, fp, det);
}

function tail(r, status) {
  const c = r.quality.callers;
  const live = status.totals;
  const liveMl = live.linear + live.ml ? live.ml / (live.linear + live.ml) : null;
  const imp = Object.entries(r.importances).slice(0, 14).map(([name, v]) => ({ name, label: factorName(name), title: name, value: v, text: fmt.num(v, 1) }));
  return h('div', { class: 'grid cols-3', style: 'margin-top:14px' },
    widget('Важность признаков', hbars(imp, { color: C.ml }), { sub: 'по CatBoost, топ-14 из ' + r.model.features.length, cls: 'span-2' }),
    widget('Скорость реакции и сверка с боем', h('dl', { class: 'kv' },
      h('dt', {}, 'Мошеннических номеров'), h('dd', {}, fmt.int(c.fraud_callers)),
      h('dt', {}, '«Проверка»'), h('dd', {}, `${pct(c.reviewed / Math.max(c.fraud_callers, 1), 0)} номеров, медиана — вызов №${c.median_calls_to_review ?? '—'}`),
      h('dt', {}, '«Блок»'), h('dd', {}, `${pct(c.blocked / Math.max(c.fraud_callers, 1), 0)} номеров, медиана — вызов №${c.median_calls_to_block ?? '—'}`),
      h('dt', {}, 'Через ML: обучение'), h('dd', {}, pct(r.quality.ml_traffic_share)),
      h('dt', {}, 'Через ML: сейчас'), h('dd', {}, liveMl === null ? 'нет вызовов' : pct(liveMl)),
      h('dt', {}, 'Калибровка'), h('dd', { class: 'mono' }, `logit·${fmt.num(r.model.platt.a, 3)} ${fmt.signed(r.model.platt.b, 3)}`))));
}
