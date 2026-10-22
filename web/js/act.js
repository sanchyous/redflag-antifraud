// «Акт решения» — формальный протокол по одному вердикту: печатная форма (диалог печати браузера,
// «Сохранить как PDF») либо прямое скачивание настоящего PDF-файла (jsPDF) — для внутреннего разбора
// и предъявления по запросу надзорного органа. Прямой ответ на требование ТЗ «решение можно отладить
// и защитить перед регулятором» — не только в виде JSON с факторами, но и в виде документа, который
// можно распечатать, подшить или отдать как файл.
//
// Данных не запрашивает: берёт уже полученный ответ /v1/calls/score (проверка вызова) или запись
// /v1/events (разбор решения в «Проблемах») — формы совпадают почти полностью, расхождения (caller
// как строка или {masked}, time/created_at) учтены в buildActData(). Печатная форма открывается в
// отдельной вкладке через клик по <a> на blob-URL, не трогая DOM панели и её стили; PDF собирается
// в памяти и отдаётся браузеру через doc.save() (jsPDF, vendor/jspdf.umd.min.js, глобал window.jspdf).

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
 * Собирает данные акта из ответа /v1/calls/score или записи /v1/events в единый плоский вид —
 * общий источник и для печатной HTML-формы (openAct), и для настоящего PDF (downloadActPdf).
 */
async function buildActData(entry) {
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
  const stageText = `${entry.stage === 'ml' ? 'ML-сервис (CatBoost, TreeSHAP)' : 'линейная модель (ядро)'}${entry.model_version ? ', версия ' + entry.model_version : ''}`;

  const rows = [
    ['Идентификатор вызова', callId],
    ['Вызов', `${callerStr} → ${calleeStr}`],
    ['Время вызова', fmt.dateTime(when)],
    ['Решение принято', stageText],
    ['Оценка риска (score)', `${score.toFixed(4)} из 1,0`],
  ];
  if (entry.safe_class) rows.push(['Защитный класс', entry.safe_class]);
  if (entry.rule_floor) rows.push(['Жёсткое правило', 'вердикт поднят независимо от модели (подмена номера или нераспределённый CLI)']);
  if (entry.block_suppressed) rows.push(['Защита от блокировки', 'блокировка заменена проверкой — защищённый класс']);
  rows.push(['Документ сформирован', fmt.dateTime(generatedAt)]);

  const factors = reasons.map((r) => ({
    name: isRule(r.factor) ? r.text : factorName(r.factor),
    value: r.value !== undefined ? fmt.num(r.value, 3) : '—',
    contribution: r.contribution === 0 ? 'правило' : fmt.signed(r.contribution),
    up: r.contribution >= 0,
    effect: r.contribution >= 0 ? 'повышает риск' : 'снижает риск',
  }));

  return {
    callId, decision, score, rows, factors,
    signalsText: signals.map((s) => signalName(s)).join(', '),
    summary: entry.summary || '',
    docNo, verdictText: DECISION_RU_FULL[decision] || decision.toUpperCase(),
  };
}

/**
 * Открывает печатную форму решения в новой вкладке. entry — см. buildActData().
 */
export async function openAct(entry) {
  const data = await buildActData(entry);
  const { callId, decision, rows, factors, signalsText, summary, docNo, verdictText } = data;

  const factorRows = factors.length
    ? factors
        .map(
          (f) => `<tr><td>${esc(f.name)}</td>
        <td class="num">${esc(f.value)}</td>
        <td class="num ${f.up ? 'up' : 'down'}">${esc(f.contribution)}</td>
        <td>${esc(f.effect)}</td></tr>`,
        )
        .join('')
    : '<tr><td colspan="4" class="muted">Рискованных факторов не найдено.</td></tr>';

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
  <table class="kv">${rows.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('')}</table>
  <div class="verdict ${esc(decision)}">${esc(verdictText)}</div>
  ${summary ? `<p>${esc(summary)}</p>` : ''}
  <table class="factors"><thead><tr><th>Фактор</th><th>Значение</th><th>Вклад</th><th>Эффект</th></tr></thead>
    <tbody>${factorRows}</tbody></table>
  ${signalsText ? `<p><b>Сработавшие сильные сигналы:</b> ${esc(signalsText)}</p>` : ''}
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

const VERDICT_COLOR = { allow: [30, 110, 60], review: [138, 81, 0], block: [186, 26, 26] };
const FONT_NAME = 'Roboto';
const FONT_FILE = 'Roboto-Cyrillic.ttf';
const FONT_URL = 'fonts/roboto-cyrillic.ttf';

let fontBase64Promise = null;

/** Шрифт грузится и кодируется в base64 один раз на вкладку, дальше переиспользуется между актами. */
function loadFontBase64() {
  if (!fontBase64Promise) {
    fontBase64Promise = fetch(FONT_URL)
      .then((r) => {
        if (!r.ok) throw new Error(`не удалось загрузить шрифт для PDF: ${r.status}`);
        return r.arrayBuffer();
      })
      .then((buf) => {
        const bytes = new Uint8Array(buf);
        let binary = '';
        const chunk = 0x8000;
        for (let i = 0; i < bytes.length; i += chunk) {
          binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
        }
        return btoa(binary);
      });
  }
  return fontBase64Promise;
}

/**
 * Формирует настоящий PDF-файл акта (без диалога печати браузера) и скачивает его. entry — см.
 * buildActData(). Текст, а не растр: taблицы и рамки рисуются примитивами jsPDF, шрифт — кириллический
 * Roboto, встроенный в PDF через addFileToVFS/addFont (он уже используется панелью, см. web/fonts/).
 */
export async function downloadActPdf(entry) {
  const { jsPDF } = window.jspdf || {};
  if (!jsPDF) throw new Error('jsPDF не загружен (vendor/jspdf.umd.min.js)');
  const data = await buildActData(entry);
  const { callId, decision, rows, factors, signalsText, summary, docNo, verdictText } = data;
  const fontBase64 = await loadFontBase64();

  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  doc.addFileToVFS(FONT_FILE, fontBase64);
  doc.addFont(FONT_FILE, FONT_NAME, 'normal');
  doc.setFont(FONT_NAME, 'normal');

  const pageW = doc.internal.pageSize.getWidth();
  const marginX = 20;
  const contentW = pageW - marginX * 2;
  let y = 18;

  doc.setFontSize(9);
  doc.setTextColor(90);
  doc.text(`Документ № ${docNo}`, pageW - marginX, y, { align: 'right' });
  y += 8;

  doc.setFontSize(13);
  doc.setTextColor(17);
  doc.text('ПРОТОКОЛ РЕШЕНИЯ СИСТЕМЫ АНТИФРОД-МОНИТОРИНГА REDFLAG', pageW / 2, y, { align: 'center', maxWidth: contentW });
  y += 6;
  doc.setFontSize(9.5);
  doc.setTextColor(85);
  doc.text('скоринг вызова по метаданным сигнализации, без содержимого разговора', pageW / 2, y, { align: 'center' });
  y += 9;

  doc.setFontSize(10);
  for (const [k, v] of rows) {
    doc.setTextColor(85);
    doc.text(String(k), marginX, y);
    doc.setTextColor(17);
    doc.text(String(v), marginX + 58, y, { maxWidth: contentW - 58 });
    doc.setDrawColor(210);
    doc.line(marginX, y + 1.6, marginX + contentW, y + 1.6);
    y += 6.5;
  }
  y += 3;

  const [vr, vg, vb] = VERDICT_COLOR[decision] || [50, 50, 50];
  doc.setDrawColor(vr, vg, vb);
  doc.setLineWidth(0.6);
  doc.rect(marginX, y, contentW, 11);
  doc.setLineWidth(0.2);
  doc.setFontSize(13);
  doc.setTextColor(vr, vg, vb);
  doc.text(verdictText, pageW / 2, y + 7.5, { align: 'center' });
  y += 17;

  if (summary) {
    doc.setFontSize(9.5);
    doc.setTextColor(30);
    const lines = doc.splitTextToSize(summary, contentW);
    doc.text(lines, marginX, y);
    y += lines.length * 4.6 + 4;
  }

  const cols = [
    { w: contentW * 0.4, label: 'Фактор' },
    { w: contentW * 0.16, label: 'Значение' },
    { w: contentW * 0.2, label: 'Вклад' },
    { w: contentW * 0.24, label: 'Эффект' },
  ];
  const rowH = 6.2;
  doc.setFontSize(9);
  doc.setFillColor(240);
  doc.rect(marginX, y, contentW, rowH, 'F');
  let cx = marginX;
  doc.setTextColor(40);
  for (const c of cols) {
    doc.text(c.label, cx + 2, y + rowH - 2);
    cx += c.w;
  }
  y += rowH;

  const factorLines = factors.length
    ? factors
    : [{ name: 'Рискованных факторов не найдено.', value: '', contribution: '', up: null, effect: '' }];
  for (const f of factorLines) {
    if (y > 270) { doc.addPage(); y = 18; } // хвост таблицы на новой странице, если акт длинный
    cx = marginX;
    doc.setTextColor(20);
    doc.text(String(f.name), cx + 2, y + rowH - 2, { maxWidth: cols[0].w - 3 });
    cx += cols[0].w;
    doc.text(String(f.value), cx + 2, y + rowH - 2);
    cx += cols[1].w;
    if (f.up !== null) doc.setTextColor(...(f.up ? [186, 26, 26] : [30, 110, 60]));
    doc.text(String(f.contribution), cx + 2, y + rowH - 2);
    doc.setTextColor(20);
    cx += cols[2].w;
    doc.text(String(f.effect), cx + 2, y + rowH - 2);
    doc.setDrawColor(210);
    doc.rect(marginX, y, contentW, rowH);
    y += rowH;
  }
  y += 4;

  if (signalsText) {
    doc.setFontSize(9.5);
    doc.setTextColor(20);
    const lines = doc.splitTextToSize(`Сработавшие сильные сигналы: ${signalsText}`, contentW);
    doc.text(lines, marginX, y);
    y += lines.length * 4.6 + 4;
  }

  y += 10;
  doc.setDrawColor(120);
  doc.line(marginX, y, marginX + contentW * 0.42, y);
  doc.line(marginX + contentW * 0.58, y, marginX + contentW, y);
  doc.setFontSize(8.5);
  doc.setTextColor(85);
  doc.text('ответственный оператор', marginX + contentW * 0.21, y + 4, { align: 'center' });
  doc.text('дата рассмотрения', marginX + contentW * 0.79, y + 4, { align: 'center' });
  y += 12;

  doc.setDrawColor(150);
  doc.line(marginX, y, marginX + contentW, y);
  y += 5;
  doc.setFontSize(7.8);
  doc.setTextColor(85);
  const footer = `Документ сформирован автоматически системой скоринга вызовов RedFlag Antifraud на основании метаданных сигнализации (номера, время, длительность, тип соединения, страна и оператор источника) — без доступа к содержимому разговора. Решение объяснимо: факторы и их вклад в оценку риска приведены выше и воспроизводимы по указанной версии модели. Контрольная сумма документа (SHA-256, первые 16 символов): ${docNo} — вычислена от идентификатора вызова, решения, оценки и времени; служит для сверки версии документа при повторной печати, а не электронной подписью.`;
  doc.text(doc.splitTextToSize(footer, contentW), marginX, y);

  doc.save(`akt-${callId}-${docNo}.pdf`);
}
