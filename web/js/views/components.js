// «Компоненты» — состояние подсистем (аналог Hosts/Latest data в Zabbix): статус-плитки и подробные показатели.

import { getStatus } from '../api.js';
import { fmt, h, widget } from '../ui.js';

/** Список статусов подсистем для виджета: { name, state: ok|warn|bad, info }. */
export function componentStatuses(s) {
  const e = s.engine;
  const out = [];
  out.push({ name: 'Ядро скоринга', state: 'ok', info: `${e.stage1.version} · ${fmt.int(e.tracked_numbers)} номеров в окнах` });

  if (!e.ml.enabled) out.push({ name: 'ML-сервис', state: 'warn', info: 'не подключён (только линейная стадия)' });
  else if (e.ml.breaker_open) out.push({ name: 'ML-сервис', state: 'bad', info: 'недоступен: breaker открыт, решает линейная стадия' });
  else if (!e.ml.active) out.push({ name: 'ML-сервис', state: 'warn', info: 'модель ещё не загружена ядром' });
  else out.push({ name: 'ML-сервис', state: 'ok', info: `${e.ml.version} · ворота ${fmt.num(e.ml.gate, 4)}` });

  if (!e.numplan.enabled) out.push({ name: 'Справочник номеров', state: 'warn', info: 'не загружен: нет регионов и операторов' });
  else out.push({ name: 'Справочник номеров', state: 'ok', info: `${fmt.int(e.numplan.ranges)} диапазонов · ${e.numplan.version}` });

  if (!s.store.enabled) out.push({ name: 'Журнал (Postgres)', state: 'warn', info: 'отключён' });
  else if (s.journal.failed > 0 || s.journal.dropped > 0) out.push({ name: 'Журнал (Postgres)', state: 'warn', info: `записано ${fmt.int(s.journal.written)}, потеряно ${fmt.int(s.journal.dropped + s.journal.failed)}` });
  else out.push({ name: 'Журнал (Postgres)', state: 'ok', info: `записано ${fmt.int(s.journal.written)}` });

  out.push({ name: 'Граф связей', state: 'ok', info: `${fmt.int(e.fan.groups)} вееров · ${fmt.int(e.fan.members)} номеров` });
  out.push({ name: 'Защитный слой', state: 'ok', info: `экстренных: ${fmt.int(s.totals.emergency)} · allowlist: ${fmt.int(e.protect.allowlist)}` });
  out.push({ name: 'Доступ к API', state: s.config.auth ? 'ok' : 'warn', info: s.config.auth ? 'ключ X-API-Key включён' : 'ключ не задан — API открыт' });
  return out;
}

export function statusList(items) {
  return h('div', { class: 'status-list' }, items.map((i) => h('div', { class: 'status ' + i.state },
    h('span', { class: 'led' }), h('span', { class: 'name' }, i.name), h('span', { class: 'info' }, i.info))));
}

function kvTable(rows) {
  return h('dl', { class: 'kv' }, rows.flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]));
}

export async function render(root) {
  const s = await getStatus();
  const e = s.engine;
  root.replaceChildren(
    h('div', { class: 'grid cols-2' },
      widget('Статусы', statusList(componentStatuses(s))),
      widget('Сервис', kvTable([
        ['Версия', s.service.version], ['Время работы', fmt.uptime(s.service.uptime_sec)], ['Go', s.service.go_version],
        ['Горутин', fmt.int(s.service.goroutines)], ['Память (heap)', fmt.num(s.service.heap_mb, 1) + ' МБ'],
        ['Пауза GC (посл.)', fmt.num(s.service.gc_pause_ms, 2) + ' мс'], ['Ядер CPU', fmt.int(s.service.cpus)],
        ['Режим при сбое', s.config.fail_open ? 'open — пропускать (allow)' : 'closed — на проверку (review)'],
      ]))),
    h('div', { class: 'grid cols-3', style: 'margin-top:14px' },
      widget('Стадия 1 — линейная модель (Go)', kvTable([
        ['Версия модели', e.stage1.version], ['Порог «проверка»', fmt.num(e.policy.review, 4)], ['Порог «блок»', fmt.num(e.policy.block, 4)],
        ['Сигналов для блока', fmt.int(e.policy.min_signals)], ['Окна по номерам', fmt.int(e.tracked_numbers)],
      ])),
      widget('Стадия 2 — ML-сервис (Python)', kvTable([
        ['Состояние', e.ml.enabled ? (e.ml.active ? 'активна' : 'неактивна') : 'не подключён'],
        ['Версия модели', e.ml.version || '—'], ['Ворота (оценка стадии 1)', e.ml.enabled ? fmt.num(e.ml.gate, 5) : '—'],
        ['Порог «проверка»', e.ml.enabled ? fmt.num(e.ml.review, 4) : '—'], ['Порог «блок»', e.ml.enabled ? fmt.num(e.ml.block, 4) : '—'],
        ['Вызовов в ML', fmt.int(s.totals.ml_calls)], ['Ошибок ML', fmt.int(s.totals.ml_errors)], ['Пропусков (breaker)', fmt.int(s.totals.ml_skipped)],
        ['Breaker', e.ml.breaker_open ? 'ОТКРЫТ' : 'закрыт'],
      ])),
      widget('Данные и журнал', kvTable([
        ['Справочник', e.numplan.enabled ? `${fmt.int(e.numplan.ranges)} диапазонов, ${fmt.int(e.numplan.regions)} регионов` : 'не загружен'],
        ['Версия справочника', e.numplan.version || '—'], ['Веера / номера', `${fmt.int(e.fan.groups)} / ${fmt.int(e.fan.members)}`],
        ['Журнал: записано', fmt.int(s.journal.written)], ['Журнал: потеряно', fmt.int(s.journal.dropped)], ['Журнал: ошибок записи', fmt.int(s.journal.failed)],
        ['Дубликатов', fmt.int(s.totals.duplicates)], ['Подъём до проверки правилом', fmt.int(s.totals.rule_floors)],
      ]))),
  );
}
