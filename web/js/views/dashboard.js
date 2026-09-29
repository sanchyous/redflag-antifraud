// Главный экран: плитки показателей, графики, причины и состояние компонентов (по мотивам дашборда Zabbix).

import { getEvents, getStats, getStatus } from '../api.js';
import { lines, ring, stackedBars } from '../charts.js';
import { factorName, signalName } from '../labels.js';
import { fmt, h, hbars, tile, widget } from '../ui.js';
import { componentStatuses, statusList } from './components.js';
import { eventTable } from './problems.js';

const COLORS = { allow: 'var(--s3)', review: 'var(--s2)', block: 'var(--red)' };

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
    { key: 'p50_us', color: 'var(--s3)', label: 'p50' }, { key: 'p95_us', color: 'var(--s2)', label: 'p95' }, { key: 'p99_us', color: 'var(--s1)', label: 'p99' },
  ], { width: 400, yFmt: (v) => fmt.us(v) }), {});

  const factors = widget('Что чаще всего повышает риск',
    hbars((stats.top_factors || []).slice(0, 7).map((f) => ({ name: f.name, label: factorName(f.name), title: f.name, value: f.count, color: 'var(--s2)' }))),
    { sub: 'проверка и блок' });

  const signals = widget('Сработавшие сильные сигналы',
    hbars((stats.top_signals || []).slice(0, 7).map((s) => ({ name: s.name, label: signalName(s.name), value: s.count, color: 'var(--red)' }))));

  const cascade = widget('Каскад решений', h('div', { style: 'display:flex;justify-content:space-around;align-items:center;gap:8px' },
    ring(1 - mlShare, { color: 'var(--s3)', label: 'линейная стадия' }), ring(mlShare, { color: 'var(--s1)', label: 'ML (CatBoost)' }), ring(flaggedShare, { color: 'var(--red)', label: 'помечено' })));

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
