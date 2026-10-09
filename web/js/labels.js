// Человекочитаемые названия факторов и сигналов (для панели). Неизвестное имя показывается как есть.

const FACTORS = {
  spoof: 'Подмена номера',
  foreign_ingress: 'Вход из-за рубежа',
  caller_unallocated: 'Номер вне диапазонов',
  out_short_share: 'Много коротких вызовов',
  out_unanswered_share: 'Много неотвеченных',
  out_regions_24h: 'Охват регионов',
  out_region_entropy: 'Равномерный обзвон регионов',
  out_gap_robot: 'Машинный ритм',
  out_calls_1h: 'Вызовов за час',
  out_calls_24h: 'Вызовов за сутки',
  out_peers_1h: 'Разных адресатов за час',
  out_peers_24h: 'Разных адресатов за сутки',
  out_novelty: 'Новые адресаты',
  call_short: 'Короткий вызов',
  call_hangup_1s: 'Отбой на 1-й секунде',
  call_night: 'Ночное время',
  call_duration: 'Длительность разговора',
  call_unanswered: 'Вызов не отвечен',
  conn_international: 'Международный транзит',
  fan_member: 'Веер номеров',
  fan_size: 'Размер веера',
  subscriber_numbers: 'Много номеров у абонента',
  operator_mismatch: 'Расхождение оператора',
  caller_invalid: 'Скрытый номер',
  in_calls_1h: 'Нагрузка на получателя',
  in_peers_24h: 'Разные звонящие получателю',
  imsi_count: 'Лишние IMSI на номере',
  chain_member: 'Цепочка переадресации',
  chain_depth: 'Глубина цепочки',
  simbox_member: 'Признак SIM-box',
  carousel_member: 'Карусель (закрытая группа)',
  rule_spoof: 'Правило: подмена номера',
  rule_unallocated: 'Правило: номер вне диапазонов',
  rule_sim_clone: 'Правило: клон SIM',
  rule_chain: 'Правило: цепочка переадресации',
  rule_sim_box: 'Правило: SIM-box',
  rule_carousel: 'Правило: карусель',
};

const SIGNALS = {
  spoof: 'подмена',
  unallocated_caller: 'нераспределённый номер',
  fan: 'веер',
  burst: 'всплеск',
  region_sweep: 'обзвон регионов',
  sim_farm: 'ферма SIM',
  robot: 'робот',
  sim_clone: 'клон SIM',
  forward_chain: 'цепочка переадресации',
  sim_box: 'SIM-box',
  carousel: 'карусель',
};

export const factorName = (f) => FACTORS[f] || f;

/** Является ли причина жёстким правилом (а не вкладом признака модели). */
export const isRule = (factor) => typeof factor === 'string' && factor.startsWith('rule_');
export const signalName = (s) => SIGNALS[s] || s;

// Типы абонентов синтетического набора (так они называются в отчёте обучения).
const KINDS = {
  regular: 'Обычные абоненты',
  heavy_user: 'Активные пользователи',
  call_center: 'Колл-центры',
  bank_notify: 'Банковские уведомления',
  courier: 'Курьеры и доставка',
  roamer: 'Роуминг',
  foreign_caller: 'Звонки из-за рубежа',
  corp_multi: 'Корпоративные мультисим',
  emergency: 'Экстренные службы',
  night_watch: 'Ночные диспетчеры и охрана',
  utility_broadcast: 'Оповещение ЖКХ/МЧС',
  spoof_burst: 'Подмена номера + всплеск',
  robocall: 'Робозвонки',
  one_ring: 'Один звонок (перезвон)',
  fan: 'Веер номеров',
  sim_farm: 'SIM-ферма',
  cold_spam: 'Холодный спам',
  imsi_clone: 'Клон SIM (лишние IMSI)',
  forward_chain: 'Цепочка переадресации',
  sim_box: 'SIM-box',
  carousel: 'Карусель (закрытая группа)',
};

export const LEGIT_KINDS = ['regular', 'heavy_user', 'call_center', 'bank_notify', 'courier', 'roamer', 'foreign_caller', 'corp_multi', 'emergency', 'night_watch', 'utility_broadcast'];
export const FRAUD_KINDS = ['spoof_burst', 'robocall', 'one_ring', 'fan', 'sim_farm', 'cold_spam', 'imsi_clone', 'forward_chain', 'sim_box', 'carousel'];
export const kindName = (k) => KINDS[k] || k;
