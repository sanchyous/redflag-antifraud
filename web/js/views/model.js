// «Веса и пороги» — то, чем принимается решение прямо сейчас: веса линейной стадии (с понятными названиями), пороги и параметры ML.
// Оператору важно видеть, какие факторы вообще влияют на решение и насколько.

import { getModel } from '../api.js';
import { factorName } from '../labels.js';
import { fmt, h, hbars, widget } from '../ui.js';

export async function render(root) {
  const m = await getModel();
  const s1 = m.stage1;
  const feats = [...s1.features].sort((a, b) => Math.abs(b.w) - Math.abs(a.w));
  const max = Math.max(...feats.map((f) => Math.abs(f.w)), 0.01);

  const weights = hbars(feats.filter((f) => Math.abs(f.w) > 1e-9).map((f) => ({
    name: f.name, label: factorName(f.name), title: f.name, value: Math.abs(f.w), max,
    color: f.w >= 0 ? 'var(--c-block)' : 'var(--c-good)', text: fmt.signed(f.w, 2),
  })), { max });

  const zero = feats.filter((f) => Math.abs(f.w) <= 1e-9);
  const ml = m.ml;

  root.replaceChildren(
    h('div', { class: 'grid cols-3' },
      widget('Стадия 1 — линейная модель', h('div', {},
        h('p', { class: 'muted', style: 'margin-top:0' }, 'Вклад = вес × (значение − эталон). Вес больше нуля повышает риск.'),
        weights,
        zero.length ? h('p', { class: 'muted', style: 'font-size:12px;margin-bottom:0' }, 'Нулевой вес: ' + zero.map((f) => factorName(f.name)).join(', ') + '.') : null),
      { cls: 'span-2', sub: s1.version }),
      widget('Пороги решения', h('dl', { class: 'kv' },
        h('dt', {}, 'Проверка'), h('dd', {}, '≥ ' + fmt.num(s1.thresholds.review, 4)),
        h('dt', {}, 'Блок'), h('dd', {}, '≥ ' + fmt.num(s1.thresholds.block, 4) + ' и не менее ' + m.min_signals + ' сильных сигналов'),
        h('dt', {}, 'Защита'), h('dd', {}, 'экстренные — «пропуск»; allowlist — без блока'),
        h('dt', {}, 'Пол-правило'), h('dd', {}, 'подмена и номер вне диапазонов — не ниже «проверки»'),
        h('dt', {}, 'Смещение'), h('dd', { class: 'mono' }, fmt.num(s1.bias, 3)))),
    ),
    h('div', { style: 'margin-top:14px' }, widget('Стадия 2 — ML-сервис (CatBoost + SHAP)', ml
      ? h('dl', { class: 'kv' },
        h('dt', {}, 'Версия'), h('dd', {}, ml.version),
        h('dt', {}, 'Порог «проверка»'), h('dd', {}, fmt.num(ml.thresholds.review, 4)),
        h('dt', {}, 'Порог «блок»'), h('dd', {}, fmt.num(ml.thresholds.block, 4)),
        h('dt', {}, 'Ворота каскада'), h('dd', {}, 'стадия 1 ≥ ' + fmt.num(ml.thresholds.gate, 5) + ' или сильный сигнал'),
        h('dt', {}, 'Метрики обучения'), h('dd', {}, Object.entries(ml.metrics || {}).map(([k, v]) => `${k}: ${fmt.num(v, 4)}`).join(' · ') || '—'),
        h('dt', {}, 'Признаков'), h('dd', {}, String(ml.features.length)))
      : h('div', { class: 'empty' }, 'ML-сервис не подключён или недоступен'))),
  );
}
