// «Акт решения» — формальный протокол по одному вердикту: печатная форма (диалог печати браузера,
// «Сохранить как PDF») для внутреннего разбора и предъявления по запросу надзорного органа. Прямой
// ответ на требование ТЗ «решение можно отладить и защитить перед регулятором» — не только в виде JSON
// с факторами, но и в виде документа, который можно распечатать и подшить.
//
// Данных не запрашивает: берёт уже полученный ответ /v1/calls/score (проверка вызова) или запись
// /v1/events (разбор решения в «Проблемах») — формы совпадают почти полностью, расхождения (caller
// как строка или {masked}, time/created_at) учтены в openAct(). Открывает отдельную вкладку через
// window.open + document.write, не трогая DOM панели и её стили.

import { fmt } from './ui.js';
import { factorName, isRule, signalName } from './labels.js';

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

const DECISION_RU_FULL = { allow: 'ПРОПУСК', review: 'ТРЕБУЕТ ПРОВЕРКИ', block: 'БЛОКИРОВКА' };

/** Контрольная сумма документа (SHA-256, первые 16 hex-знаков от ключевых полей решения) — не
 * электронная подпись, а ссылочный идентификатор версии для сверки при повторной печати. */
async function checksum(parts) {
  const data = new TextEncoder().encode(parts.join('|'));
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}

/**
 * Открывает печатную форму решения в новой вкладке. entry — ответ /v1/calls/score или запись
 * /v1/events: call_id, caller/callee (строка или {masked}), decision, score, stage, reasons[],
 * signals[], summary, time|created_at, latency_us, safe_class?, rule_floor?, block_suppressed?,
 * model_version?.
 */
export async function openAct(entry) {
  const callerStr = typeof entry.caller === 'string' ? entry.caller : entry.caller?.masked || '(скрыт)';
  const calleeStr = typeof entry.callee === 'string' ? entry.callee : entry.callee?.masked || '?';
  const when = entry.time || entry.created_at || Date.now();
  const callId = entry.call_id || '—';
  const decision = entry.decision || 'allow';
  const score = Number(entry.score ?? 0);
  const reasons = entry.reasons || [];
  const signals = entry.signals || [];
  const docNo = await checksum([callId, decision, score.toFixed(4), String(when)]);
  const generatedAt = new Date();

  const factorRows = reasons.length
    ? reasons
        .map(
          (r) => `<tr><td>${esc(isRule(r.factor) ? r.text : factorName(r.factor))}</td>
        <td class="num">${r.value !== undefined ? esc(fmt.num(r.value, 3)) : '—'}</td>
        <td class="num ${r.contribution >= 0 ? 'up' : 'down'}">${r.contribution === 0 ? 'правило' : esc(fmt.signed(r.contribution))}</td>
        <td>${r.contribution >= 0 ? 'повышает риск' : 'снижает риск'}</td></tr>`,
        )
        .join('')
    : '<tr><td colspan="4" class="muted">Рискованных факторов не найдено.</td></tr>';

  const rows = [
    ['Идентификатор вызова', esc(callId)],
    ['Вызов', `${esc(callerStr)} &rarr; ${esc(calleeStr)}`],
    ['Время вызова', esc(fmt.dateTime(when))],
    ['Решение принято', `${esc(entry.stage === 'ml' ? 'ML-сервис (CatBoost, TreeSHAP)' : 'линейная модель (ядро)')}${entry.model_version ? ', версия ' + esc(entry.model_version) : ''}`],
    ['Оценка риска (score)', `${score.toFixed(4)} из 1,0`],
  ];
  if (entry.safe_class) rows.push(['Защитный класс', esc(entry.safe_class)]);
  if (entry.rule_floor) rows.push(['Жёсткое правило', 'вердикт поднят независимо от модели (подмена номера или нераспределённый CLI)']);
  if (entry.block_suppressed) rows.push(['Защита от блокировки', 'блокировка заменена проверкой — защищённый класс']);
  rows.push(['Документ сформирован', esc(fmt.dateTime(generatedAt))]);

  const html = `<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>Акт № ${docNo} — ${esc(callId)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: "PT Serif", "Times New Roman", Georgia, serif; color: #111; background: #fff;
    max-width: 780px; margin: 32px auto; padding: 0 20px; line-height: 1.5; }
  h1 { font-size: 16px; text-align: center; text-transform: uppercase; letter-spacing: .03em; margin: 0 0 4px; }
  .sub { text-align: center; color: #555; font-size: 12px; margin-bottom: 22px; }
  .docno { text-align: right; font-size: 12px; color: #555; margin-bottom: 14px; }
  table.kv { width: 100%; border-collapse: collapse; margin-bottom: 18px; }
  table.kv td { padding: 4px 6px; border-bottom: 1px dotted #ccc; font-size: 13px; vertical-align: top; }
  table.kv td:first-child { width: 230px; color: #555; }
  .verdict { text-align: center; font-size: 20px; font-weight: bold; letter-spacing: .04em; margin: 18px 0; padding: 10px; border: 2px solid #111; }
  .verdict.allow { border-color: #1e6e3c; color: #1e6e3c; }
  .verdict.review { border-color: #8a5100; color: #8a5100; }
  .verdict.block { border-color: #ba1a1a; color: #ba1a1a; }
  table.factors { width: 100%; border-collapse: collapse; margin: 10px 0 20px; font-size: 12.5px; }
  table.factors th, table.factors td { border: 1px solid #bbb; padding: 5px 8px; text-align: left; }
  table.factors th { background: #f0f0f0; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  td.up { color: #ba1a1a; } td.down { color: #1e6e3c; }
  .muted { color: #777; }
  .foot { margin-top: 32px; font-size: 11.5px; color: #555; border-top: 1px solid #999; padding-top: 10px; }
  .sign { margin-top: 36px; display: flex; justify-content: space-between; font-size: 12px; }
  .sign div { width: 45%; border-top: 1px solid #333; padding-top: 4px; text-align: center; color: #555; }
  .noprint { text-align: center; margin-bottom: 20px; }
  .noprint button { font: inherit; padding: 8px 18px; cursor: pointer; }
  @media print { body { margin: 0; max-width: none; } .noprint { display: none; } }
</style></head><body>
  <div class="noprint"><button onclick="window.print()">Печать / сохранить как PDF</button></div>
  <div class="docno">Документ № ${docNo}</div>
  <h1>Протокол решения системы антифрод-мониторинга RedFlag</h1>
  <div class="sub">скоринг вызова по метаданным сигнализации, без содержимого разговора</div>
  <table class="kv">${rows.map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join('')}</table>
  <div class="verdict ${esc(decision)}">${esc(DECISION_RU_FULL[decision] || decision.toUpperCase())}</div>
  ${entry.summary ? `<p>${esc(entry.summary)}</p>` : ''}
  <table class="factors"><thead><tr><th>Фактор</th><th>Значение</th><th>Вклад</th><th>Эффект</th></tr></thead>
    <tbody>${factorRows}</tbody></table>
  ${signals.length ? `<p><b>Сработавшие сильные сигналы:</b> ${signals.map((s) => esc(signalName(s))).join(', ')}</p>` : ''}
  <div class="sign"><div>ответственный оператор</div><div>дата рассмотрения</div></div>
  <div class="foot">
    Документ сформирован автоматически системой скоринга вызовов RedFlag Antifraud на основании метаданных
    сигнализации (номера, время, длительность, тип соединения, страна и оператор источника) — без доступа
    к содержимому разговора. Решение объяснимо: факторы и их вклад в оценку риска приведены выше и
    воспроизводимы по указанной версии модели. Контрольная сумма документа (SHA-256, первые 16 символов):
    <code>${docNo}</code> — вычислена от идентификатора вызова, решения, оценки и времени; служит для
    сверки версии документа при повторной печати, а не электронной подписью.
  </div>
</body></html>`;

  // Открываем через клик по <a target="_blank"> на blob-URL, а не window.open(): блокировщики всплывающих
  // окон целятся именно в window.open (в том числе после await — счёт идёт на доли секунды с момента
  // клика), а переход по ссылке — даже созданной и кликнутой скриптом — так агрессивно не режут.
  const url = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
  const a = document.createElement('a');
  a.href = url;
  a.target = '_blank';
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000); // новая вкладка успевает загрузить документ из blob
}
