# Как вливать код (читать до первого коммита)

## Правила — их всего 4
1. **В `main` напрямую не пушим.** Только через Pull Request — мержит владелец после ревью.
2. **Ветка на каждую задачу**: `feature/кратко-суть` или `fix/кратко-суть`.
3. **CI должен быть зелёным** — красный PR не принимается, чиним.
4. **Никаких секретов в коммитах**: пароли, ключи, `.env` — запрещено (репо приватный, но история вечная).

## Настройка один раз
```bash
# 1) свой SSH-ключ (если ещё нет)
ssh-keygen -t ed25519 -C "твой@email"
cat ~/.ssh/id_ed25519.pub   # добавить его в GitHub → Settings → SSH and GPG keys

# 2) склонировать (после инвайта в коллабораторы)
git clone git@github.com:sanchyous/redflag-antifraud.git
cd redflag-antifraud
```

## Рабочий цикл (каждая задача)
```bash
git checkout main && git pull          # свежий main
git checkout -b feature/transaction-scorer   # своя ветка

# ... пишешь код, тестируешь локально ...

git add -A
git commit -m "Add transaction scoring endpoint"   # суть одной строкой
git push -u origin feature/transaction-scorer
```
GitHub в выводе покажет ссылку **Create pull request** → открой PR → в описании 2–3 строки: что делает и как проверить.

## Что дальше
- CI (тесты + сборка) прогонится сам по твоему PR.
- Правки по ревью — просто новые коммиты в **ту же ветку** + `git push`, PR обновится сам.
- После мержа твою ветку можно удалить: `git branch -d feature/transaction-scorer`.

## Если main убежал вперёд во время твоей работы
```bash
git checkout main && git pull
git checkout твоя-ветка
git rebase main     # конфликты решаем сами, НЕ в main
```

## Запрещено (сломает всем работу)
- `git push --force` в любые ветки кроме своих feature-веток
- прямые коммиты в `main`
- коммиты с `.env`, паролями, токенами, ключами
- мержить свой PR самому
