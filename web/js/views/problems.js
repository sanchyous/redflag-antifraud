// «Проблемы» — рискованные решения (проверка и блок), по аналогии с Problems в Zabbix. Клик по строке открывает
// разбор: факторы с вкладом в решение (то самое «объяснение», которого требует ТЗ).

import { openAct } from '../act.js';
import { getEvents, getStatus } from '../api.js';
import { factorName, isRule, signalName } from '../labels.js';
import { fmt, h, openDrawer, sevBadge, toast, widget } from '../ui.js';

const STRONG = new Set(['spoof', 'unallocated_caller', 'fan']);

/** Пороги решения для стадии события — чтобы показать score не абстрактным числом,
 * а на фоне границы, которую он пересёк (или не пересёк). thresholds — { stage1: {review,block}, ml: {review,block} }. */
function stageThresholds(e, thresholds) {
  if (!thresholds) return null;
  return e.stage === 'ml' ? thresholds.ml : thresholds.stage1;
}

function scoreWithThreshold(e, thresholds) {
  const t = stageThresholds(e, thresholds);
  if (!t) return e.score.toFixed(4);
  const near = e.decision === 'block' ? t.block : t.review;
  return `${e.score.toFixed(4)} (порог ${e.decision === 'block' ? 'блока' : 'проверки'} ${near.toFixed(4)})`;
}

/** Таблица событий. compact — без столбца стадии и времени в полном виде. thresholds — см. scoreWithThreshold. */
export function eventTable(items, { compact = false, thresholds } = {}) {
  const head = h('tr', {}, h('th', {}, 'Время'), h('th', {}, 'Серьёзность'), h('th', {}, 'Вызов'), h('th', {}, 'Причина'),
    h('th', { class: 'num' }, 'Score'), compact ? null : h('th', {}, 'Стадия'), compact ? null : h('th', {}, 'Сигналы'));
  const rows = items.map((e) => {
    const top = (e.reasons || []).find((r) => r.effect === 'raises');
    return h('tr', { class: 'row', onclick: () => openEvent(e, thresholds) },
      h('td', { class: 'muted', title: fmt.dateTime(e.time) }, compact ? fmt.ago(e.time) : fmt.dateTime(e.time)),
      h('td', {}, sevBadge(e.decision)),
      h('td', {}, h('div', { class: 'mono' }, `${e.caller} → ${e.callee}`), h('div', { class: 'muted', style: 'font-size:12px' }, regionLine(e))),
      h('td', {}, top ? top.text : '—', e.rule_floor ? h('span', { class: 'chip hot', title: 'вердикт поднят жёстким правилом' }, 'правило') : null),
      h('td', { class: 'num' }, e.score.toFixed(4)),
      compact ? null : h('td', {}, e.stage === 'ml' ? 'ML' : 'линейная'),
      compact ? null : h('td', {}, (e.signals || []).map((s) => h('span', { class: 'chip' + (STRONG.has(s) ? ' hot' : '') }, signalName(s)))));
  });
  return h('div', { class: 'table-wrap' }, h('table', {}, h('thead', {}, head), h('tbody', {}, rows)));
}

function regionLine(e) {
  const a = e.caller_region || '?';
  const b = e.callee_region || '?';
  return `${a} → ${b}`;
}

/** Панель разбора: решение, сигналы и вклад каждого фактора (полоса вправо — повышает риск, влево — снижает). */
export function openEvent(e, thresholds) {
  const reasons = e.reasons || [];
  const maxAbs = Math.max(0.01, ...reasons.map((r) => Math.abs(r.contribution)));
  const contrib = h('div', {}, reasons.map((r) => {
    const w = (Math.abs(r.contribution) / maxAbs) * 50;
    const up = r.contribution >= 0;
    return h('div', { style: 'margin:10px 0' },
      h('div', { style: 'display:flex;justify-content:space-between;gap:10px;font-size:13px' },
        h('span', {}, isRule(r.factor) ? h('b', {}, r.text) : [h('b', {}, factorName(r.factor)), h('span', { class: 'muted' }, ' — ' + r.text)]),
        h('span', { class: 'mono', style: `color:${up ? 'var(--c-block)' : 'var(--c-good)'}` }, r.contribution === 0 ? 'правило' : fmt.signed(r.contribution))),
      h('div', { style: 'position:relative;height:10px;background:var(--panel-head);border:1px solid var(--line);border-radius:5px;margin-top:4px' },
        h('div', { style: 'position:absolute;left:50%;top:0;bottom:0;width:1px;background:var(--line)' }),
        h('div', { style: `position:absolute;top:0;bottom:0;border-radius:5px;background:${up ? 'var(--c-block)' : 'var(--c-good)'};${up ? 'left:50%;' : `right:50%;`}width:${w}%` })));
  }));
  const kv = h('dl', { class: 'kv' },
    h('dt', {}, 'Решение'), h('dd', {}, sevBadge(e.decision)),
    h('dt', {}, 'Score'), h('dd', {}, scoreWithThreshold(e, thresholds)),
    h('dt', {}, 'Стадия'), h('dd', {}, e.stage === 'ml' ? 'ML (CatBoost) — вклад факторов посчитан SHAP, не точной формулой' : 'линейная модель — вклад факторов посчитан точно'),
    h('dt', {}, 'Вызов'), h('dd', { class: 'mono' }, `${e.caller} → ${e.callee}`),
    h('dt', {}, 'Регионы'), h('dd', {}, regionLine(e)),
    h('dt', {}, 'Идентификатор'), h('dd', { class: 'mono' }, e.call_id),
    h('dt', {}, 'Время'), h('dd', {}, fmt.dateTime(e.time)),
    h('dt', {}, 'Сигналы'), h('dd', {}, (e.signals || []).length ? e.signals.map((s) => h('span', { class: 'chip hot' }, signalName(s))) : '—'),
    h('dt', {}, 'Задержка'), h('dd', {}, fmt.us(e.latency_us)),
    e.rule_floor ? h('dt', {}, 'Пол-правило') : null,
    e.rule_floor ? h('dd', {}, (reasons.find((r) => isRule(r.factor)) || {}).text || 'Вердикт поднят жёстким правилом независимо от модели.') : null,
    e.block_suppressed ? h('dt', {}, 'Защита') : null,
    e.block_suppressed ? h('dd', {}, 'Блок заменён проверкой: защитный класс.') : null);
  openDrawer('Разбор решения', h('div', {}, e.summary ? h('p', { style: 'margin:0 0 14px;line-height:1.45' }, e.summary) : null, kv,
    h('button', { class: 'btn ghost small', type: 'button', style: 'margin:10px 0', onclick: () => openAct(e).catch((err) => toast(err.message, true)) }, 'Сформировать акт для надзорного органа'),
    h('h3', { style: 'margin:18px 0 4px;font-size:14px' }, 'Факторы'),
    h('div', { class: 'muted', style: 'font-size:12px' }, 'вправо — повышает риск, влево — снижает'), contrib));
}

export async function render(root, ctx) {
  const filter = ctx.problemsFilter || '';
  const [data, status] = await Promise.all([getEvents(100, filter), getStatus()]);
  const thresholds = { stage1: status.engine.stage1, ml: status.engine.ml };
  const btn = (value, label) => h('button', {
    class: 'btn small' + (filter === value ? '' : ' ghost'), style: 'margin-right:6px',
    onclick: () => { ctx.problemsFilter = value; ctx.rerender(); },
  }, label);
  root.replaceChildren(widget('Рискованные вызовы',
    data.items.length ? eventTable(data.items, { thresholds }) : h('div', { class: 'empty' }, 'Рискованных вызовов нет'),
    { sub: h('span', {}, btn('', 'все'), btn('block', 'блокировки'), btn('review', 'проверки')), flush: true }));
}
