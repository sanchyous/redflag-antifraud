// «Проверка вызова» — интерактивный скоринг одного вызова. Готовые сценарии повторяют пример из ТЗ и ключевые случаи;
// результат показан как в ТЗ: вызов → решение и факторы с вкладом.

import { scoreCall } from '../api.js';
import { factorName, isRule, signalName } from '../labels.js';
import { DECISION_RU, fmt, h, toast, widget } from '../ui.js';

const nowIso = () => {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? '+' : '-';
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}${sign}${p(Math.floor(Math.abs(off) / 60))}:${p(Math.abs(off) % 60)}`;
};

const PRESETS = [
  { label: 'Пример из ТЗ', hint: '+7 495 ***-**-12 → +7 916 ***-**-83, 6 с, вход из-за рубежа',
    call: { caller: '+7 495 ***-**-12', callee: '+7 916 ***-**-83', duration_sec: 6, src_country: 'DE' } },
  { label: 'Вызов скорой (103)', hint: 'даже с подозрительным источником — всегда «пропуск»',
    call: { caller: '+7 495 123-45-67', callee: '*103#', duration_sec: 2, src_country: 'DE' } },
  { label: 'Обычный разговор', hint: 'четыре минуты между двумя абонентами',
    call: { caller: '+7 916 123-45-67', callee: '+7 495 765-43-21', duration_sec: 240 } },
  { label: 'Номер вне диапазонов', hint: 'российский номер, которого нет в реестре Россвязи',
    call: { caller: '+7 999 123-45-67', callee: '+7 916 765-43-21', duration_sec: 4 } },
  { label: 'Скрытый номер', hint: 'звонящий не передан',
    call: { caller: '', callee: '+7 916 765-43-21', duration_sec: 3 } },
  { label: 'Иностранный номер', hint: 'честный иностранный звонящий: вход из-за рубежа, но не подмена',
    call: { caller: '+49 30 12345678', callee: '+7 916 765-43-21', duration_sec: 90, src_country: 'DE', conn_type: 'international' } },
];

const randomId = () => 'ui-' + Math.random().toString(36).slice(2, 10);

export async function render(root, ctx) {
  const form = ctx.playground || (ctx.playground = { caller: '+7 495 ***-**-12', callee: '+7 916 ***-**-83', duration_sec: 6, src_country: 'DE', conn_type: '', answered: '' });
  const result = h('div', {});

  const field = (name, label, attrs = {}) => h('label', { class: attrs.wide ? 'wide' : '' }, label,
    h('input', { name, value: form[name] ?? '', placeholder: attrs.placeholder || '', type: attrs.type || 'text',
      oninput: (e) => { form[name] = e.target.value; } }));
  const select = (name, label, options) => h('label', {}, label,
    h('select', { name, onchange: (e) => { form[name] = e.target.value; } },
      options.map(([v, t]) => h('option', { value: v, selected: (form[name] ?? '') === v }, t))));

  const setPreset = (p) => {
    Object.assign(form, { caller: '', callee: '', duration_sec: 0, src_country: '', conn_type: '', answered: '' }, p.call);
    ctx.rerender();
  };

  async function submit(ev) {
    ev?.preventDefault();
    const call = { call_id: randomId(), caller: form.caller, callee: form.callee, started_at: nowIso(), duration_sec: Number(form.duration_sec) || 0 };
    if (form.src_country) call.src_country = form.src_country;
    if (form.conn_type) call.conn_type = form.conn_type;
    if (form.answered !== '') call.answered = form.answered === 'true';
    button.disabled = true;
    try {
      const r = await scoreCall(call);
      result.replaceChildren(verdictCard(r));
    } catch (e) {
      result.replaceChildren(h('div', { class: 'empty' }, `Ошибка: ${e.message}${e.body?.error ? ' (' + e.body.error + ')' : ''}`));
      toast('Вызов не принят: ' + e.message, true);
    } finally {
      button.disabled = false;
    }
  }

  const button = h('button', { class: 'btn', type: 'submit' }, 'Оценить вызов');
  const formEl = h('form', { onsubmit: submit },
    h('div', { class: 'presets' }, PRESETS.map((p) => h('button', { class: 'btn ghost small', type: 'button', title: p.hint, onclick: () => setPreset(p) }, p.label))),
    h('div', { class: 'form' },
      field('caller', 'Звонящий (номер или маска)', { placeholder: '+7 495 ***-**-12' }),
      field('callee', 'Получатель', { placeholder: '+7 916 ***-**-83' }),
      field('duration_sec', 'Длительность, с', { type: 'number' }),
      field('src_country', 'Страна источника (ISO)', { placeholder: 'DE' }),
      select('conn_type', 'Тип соединения', [['', 'не указан'], ['mobile', 'мобильное'], ['fixed', 'городское'], ['international', 'международное'], ['voip', 'VoIP']]),
      select('answered', 'Вызов принят', [['', 'по длительности'], ['true', 'да'], ['false', 'нет']]),
      h('div', { class: 'wide' }, button)));

  root.replaceChildren(h('div', { class: 'grid cols-2' },
    widget('Параметры вызова', formEl),
    widget('Решение', result)));
  result.replaceChildren(h('div', { class: 'empty' }, 'Выберите сценарий и нажмите «Оценить вызов»'));
}

export function verdictCard(r) {
  const reasons = r.reasons || [];
  const maxAbs = Math.max(0.01, ...reasons.map((x) => Math.abs(x.contribution)));
  const chips = (r.signals || []).map((s) => h('span', { class: 'chip hot' }, signalName(s)));
  return h('div', {},
    h('div', { class: 'verdict ' + r.decision },
      h('div', {}, h('div', { class: 'big' }, (DECISION_RU[r.decision] || r.decision).toUpperCase()),
        h('div', { class: 'muted' }, `score ${r.score.toFixed(4)} · ${r.stage === 'ml' ? 'ML' : 'линейная модель'} · ${fmt.us(r.latency_us)}`)),
      h('div', { class: 'scorebar', title: 'вероятность риска' }, h('i', { style: `width:${Math.min(100, Math.max(2, r.score * 100))}%` }))),
    r.summary ? h('p', { style: 'margin:0 0 10px;font-size:14px;line-height:1.45' }, r.summary) : null,
    h('div', { style: 'margin-bottom:8px' }, h('span', { class: 'mono' }, `${r.caller.masked || '(скрыт)'} → ${r.callee.masked || '?'}`)),
    h('div', { class: 'muted', style: 'margin-bottom:8px;font-size:13px' },
      `${r.caller.region || '?'}${r.caller.operator ? ' · ' + r.caller.operator : ''} → ${r.callee.region || '?'}${r.callee.operator ? ' · ' + r.callee.operator : ''}`),
    r.safe_class ? h('div', { style: 'margin-bottom:8px' }, h('span', { class: 'chip' }, 'защитный класс: ' + r.safe_class)) : null,
    r.rule_floor ? h('div', { class: 'chip hot' }, 'правило: подмена номера') : null,
    r.block_suppressed ? h('div', { class: 'chip' }, 'блок заменён проверкой') : null,
    chips.length ? h('div', { style: 'margin:8px 0' }, chips) : null,
    h('h3', { style: 'margin:14px 0 4px;font-size:14px' }, 'Факторы'),
    reasons.length ? reasons.map((x) => {
      const up = x.contribution >= 0;
      return h('div', { style: 'margin:9px 0' },
        h('div', { style: 'display:flex;justify-content:space-between;gap:10px;font-size:13px' },
          h('span', {}, isRule(x.factor) ? h('b', {}, x.text) : [h('b', {}, factorName(x.factor)), h('span', { class: 'muted' }, ' — ' + x.text)]),
          h('span', { class: 'mono', style: `color:${up ? 'var(--c-block)' : 'var(--c-good)'}` }, x.contribution === 0 ? 'правило' : fmt.signed(x.contribution))),
        h('div', { style: 'position:relative;height:10px;background:var(--panel-head);border:1px solid var(--line);border-radius:5px;margin-top:4px' },
          h('div', { style: 'position:absolute;left:50%;top:0;bottom:0;width:1px;background:var(--line)' }),
          h('div', { style: `position:absolute;top:0;bottom:0;border-radius:5px;background:${up ? 'var(--c-block)' : 'var(--c-good)'};${up ? 'left:50%;' : 'right:50%;'}width:${(Math.abs(x.contribution) / maxAbs) * 50}%` })));
    }) : h('div', { class: 'muted' }, 'Рискованных факторов нет'));
}
