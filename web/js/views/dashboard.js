// Главный экран: плитки показателей, графики, причины и состояние компонентов (по мотивам дашборда Zabbix).

import { getEvents, getStats, getStatus } from '../api.js';
import { lines, ring, stackedBars } from '../charts.js';
import { factorName, signalName } from '../labels.js';
import { fmt, h, hbars, tile, widget } from '../ui.js';
import { componentStatuses, statusList } from './components.js';
import { eventTable } from './problems.js';

const COLORS = { allow: 'var(--c-good)', review: 'var(--c-review)', block: 'var(--c-block)' };

export async function render(root, ctx) {
  const points = 60;
  const [status, stats, events] = await Promise.all([getStatus(), getStats(ctx.windowSec, points), getEvents(8)]);
  const t = stats.totals;
  const total = t.total || 0;
  const flaggedShare = total ? (t.review + t.block) / total : 0;
  const rps = stats.points.length ? stats.points.reduce((s, p) => s + p.rps, 0) / stats.points.length : 0;
  const last = [...stats.points].reverse().find((p) => p.total > 0) || {};
  const p99 = t.p99_us;
  const mlShare = total ? t.ml / total : 0;
  const ml = status.engine.ml;

  const kpis = h('div', { class: 'grid cols-6' },
    tile('Решений', fmt.int(total), `за ${ctx.windowLabel}`, 'info'),
    tile('Скорость', fmt.num(rps, 1) + ' /с', `сейчас ${fmt.num(last.rps || 0, 1)} /с`, ''),
    tile('Проверка', fmt.pct(total ? t.review / total : 0, 2), `${fmt.int(t.review)} вызовов`, t.review ? 'avg' : 'ok'),
    tile('Блокировки', fmt.pct(total ? t.block / total : 0, 2), `${fmt.int(t.block)} вызовов`, t.block ? 'high' : 'ok'),
    tile('Задержка p99', fmt.us(p99), `p50 ${fmt.us(t.p50_us)}`, p99 > 50000 ? 'high' : p99 > 10000 ? 'warn' : 'ok'),
    tile('Через ML', fmt.pct(mlShare, 1), ml.enabled ? (ml.active ? 'стадия 2 активна' : 'ML недоступен') : 'ML не подключён', ml.enabled && !ml.active ? 'warn' : ''),
  );

  const decisions = widget('Решения по времени', stackedBars(stats.points, [
    { key: 'allow', color: COLORS.allow, label: 'Пропуск' }, { key: 'review', color: COLORS.review, label: 'Проверка' }, { key: 'block', color: COLORS.block, label: 'Блок' },
  ]), { sub: `шаг ${stats.step_sec} с`, cls: 'span-2' });

  const latency = widget('Задержка скоринга', lines(stats.points, [
    { key: 'p50_us', color: 'var(--c-info)', label: 'p50' }, { key: 'p95_us', color: 'var(--c-review)', label: 'p95' }, { key: 'p99_us', color: 'var(--c-block)', label: 'p99' },
  ], { width: 400, yFmt: (v) => fmt.us(v) }), {});

  const factors = widget('Что чаще всего повышает риск',
    hbars((stats.top_factors || []).slice(0, 7).map((f) => ({ name: f.name, label: factorName(f.name), title: f.name, value: f.count, color: 'var(--c-review)' }))),
    { sub: 'проверка и блок' });

  const signals = widget('Сработавшие сильные сигналы',
    hbars((stats.top_signals || []).slice(0, 7).map((s) => ({ name: s.name, label: signalName(s.name), value: s.count, color: 'var(--c-block)' }))));

  const allT = status.totals || {};
  const cascade = widget('Каскад решений', h('div', {},
    h('div', { style: 'display:flex;justify-content:space-around;align-items:center;gap:8px' },
      ring(1 - mlShare, { color: 'var(--c-info)', label: 'линейная стадия' }), ring(mlShare, { color: 'var(--c-good)', label: 'ML (CatBoost)' }), ring(flaggedShare, { color: 'var(--c-review)', label: 'помечено' })),
    h('p', { class: 'muted', style: 'margin:16px 0 10px' },
      'Весь трафик сначала проходит линейную стадию (микросекунды). В ML уходит только спорная «серая зона» — оценка рядом с порогом или сработавший сильный сигнал.'),
    h('dl', { class: 'kv' },
      h('dt', {}, 'Жёсткий пол'),
      h('dd', {}, `${fmt.int(t.floors)} вызовов за ${ctx.windowLabel} — подмена, номер вне диапазонов, клон SIM, цепочка переадресации, SIM-box или карусель поднимают вердикт до «проверки» независимо от веса модели`),
      h('dt', {}, 'Вызовы к ML-сервису'),
      h('dd', {}, `${fmt.int(allT.ml_calls || 0)} успешно, ${fmt.int(allT.ml_errors || 0)} ошибок, ${fmt.int(allT.ml_skipped || 0)} пропущено (откат на линейную стадию) — с запуска сервиса`),
      h('dt', {}, 'Повторная доставка'),
      h('dd', {}, `${fmt.int(t.duplicates)} за ${ctx.windowLabel} — учтена один раз по call_id`),
    )));

  const health = widget('Состояние компонентов', statusList(componentStatuses(status)), { sub: `версия ${status.service.version}` });

  const problems = widget('Последние проблемы', events.items.length ? eventTable(events.items, { compact: true }) : h('div', { class: 'empty' }, 'Рискованных вызовов пока нет'),
    { sub: h('a', { href: '#/problems' }, 'все →'), flush: true, cls: 'span-2' });

  root.replaceChildren(
    kpis,
    h('div', { class: 'grid cols-3', style: 'margin-top:14px' }, decisions, health),
    h('div', { class: 'grid cols-3', style: 'margin-top:14px' }, latency, factors, signals),
    h('div', { class: 'grid cols-3', style: 'margin-top:14px' }, cascade, problems),
  );
}
