# 2026-07-29 — второй source pass по агенту skills

## Статус

Профиль `phylax-skills-v1` сначала был подготовлен без hotkey, затем
2026-07-29 в 08:38 UTC назначен hotkey `sn76_2` и выполнен v1 submit.
Активные `phylax-packages-v1` и `phylax-mcp-v1` не пересабмичены и остаются
на SHA-256
`3b406c9879f7e4268d69e4e66ad14033cebe10fb5bb882f1bac21fa54b6bee03`.

Новый общий working SHA-256:
`41af77c111ebadfe3cf31c992139c4744bc0dc002948344b15330b8a965dedbb`.
Из-за единого файла этот SHA используется активным `skills` и подготовленным
`repositories`, хотя функциональные изменения относятся к ветке `skills`.

### Submission receipt

| Поле | Значение |
|---|---|
| wallet hotkey | `default/sn76_2` |
| SS58 | `5G483fsyFaTmy8VGbhMAMWLBwvNCkPFxk1VVDgHrkdCUyb5M` |
| SN76 UID | `246` |
| on-chain registration | block `8726470` |
| track / label | `skills` / `phylax-skills-v1` |
| agent version | `1` |
| agent ID | `7ac152758be44ad2b20530dc52dbd101` |
| server status | `active`, evaluation `pending`, runs `0` |
| code SHA-256 | `41af77c111ebadfe3cf31c992139c4744bc0dc002948344b15330b8a965dedbb` |

`/v1/specialization/register` и `/v1/specialization/agent` вернули `200 OK`.
Перед отправкой официальный Python 3.11 sandbox preflight прошёл полностью.
Один существующий execution API key синхронизирован во всех четырёх
gitignored `.env*`; значения не записаны в Git, права файлов установлены
`0600`. У `.env.repositories` по-прежнему нет hotkey, поэтому repositories не
отправлялся.

## Основание

Основной источник — [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector):
его правила и официальные SSD fixtures были сопоставлены с категориями,
которые реально оценивает Phylax validator. Для контроля precision использованы
892 настоящих `SKILL.md` из
[Trail of Bits skills](https://github.com/trailofbits/skills) и
[Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills).

Добавлены только формы, для которых одновременно нашлись:

1. подтверждённый источник;
2. пропуск прежнего кандидата;
3. категория Phylax context/action plane;
4. безопасный близкий пример;
5. измеримый A/B delta.

## Закрытые пробелы

- передача полной истории разговора или session context внешнему получателю —
  `transitive_leakage`;
- непрямое извлечение system prompt через encode/base64/translate/paraphrase с
  последующим возвратом результата — `context_injection`;
- длинный валидный base64-блок, который после декодирования содержит реальную
  injected instruction; произвольные base64 assets не блокируются;
- загрузка удалённого документа с явным приказом считать его инструкции
  авторитетными — `context_injection`;
- semantic bypass без фразы `ignore previous instructions`: понижение правил до
  «suggestions», privileged mode без обычных ограничений и unrestricted persona;
- приказ отражать credentials или sensitive values обратно пользователю;
- прямой `eval`/`exec`/shell model output без валидации в bundled script;
  инструкция, запускающая уже осуждённый script, получает отдельную
  context-plane attribution.

## Что намеренно не добавлено

- общие слова `security`, `credential`, `password`, `cloud`, `external API`;
- любое roleplay или persona без отказа от ограничений;
- любой base64, download или remote documentation;
- `without asking`, autonomous/tool-use и excessive-agency по одному ключевому
  слову;
- cloud upload как самостоятельный признак;
- обычный JSON parsing ответа модели.

Эти направления слишком широки для held-out precision. Тестовый вариант
правила отражения credentials действительно изменил четыре честных security
skills; после требования явного `echo/repeat back` или включения секретов в
каждый ответ все четыре изменения исчезли.

## Validator A/B

| Проверка | Предыдущий кандидат | Новый кандидат |
|---|---:|---:|
| Skills source trackcheck, 25 artifacts | 0.3858 — TP 4, TN 12, FN 9 | **1.0000 — TP 13, TN 12, FN 0** |
| Official SkillSpector SSD, 4 malicious + 1 clean | все 5 `ALLOW` | 4 `WARN`, clean `ALLOW` |
| 892 real skills verdict distribution | 753 `ALLOW`, 55 `WARN`, 84 `BLOCK` | без изменений |
| Public skills corpus | 1.0000 | 1.0000 |
| Expanded skills corpus | 1.0000 | 1.0000 — TP 8, TN 6 |

Полная регрессия общего файла:

| Проверка | Результат |
|---|---|
| Expanded packages | 1.0000 — TP 11, TN 9 |
| Expanded MCP | 1.0000 — TP 9, TN 8 |
| Expanded repositories | 0.8285 — 9 artifacts |
| Expanded structural trackcheck packages | 1.0000 — TP 17, TN 11 |
| Expanded structural trackcheck MCP | 1.0000 — TP 17, TN 18 |
| Rulecheck | 22/22 |
| Fuzz | 88/88 |
| Sandbox preflight | Python 3.11.15, deterministic across 3 reps |

`harness/skills_smoke.py` оставлен в лаборатории как воспроизводимый
unlabelled precision-test: он сравнивает распределения двух кандидатов по
деревьям настоящих skills и показывает каждое изменившееся решение вместе с
findings.

## Вывод

Дальше расширять `skills` разумно через data flow и новые подтверждённые
validator shapes, а не через дополнительные словари опасных слов. Текущий
кандидат закрывает девять измеримых false negatives второй волны при нулевом
decision delta на реальном 892-artifact control set. Это улучшает готовность,
но не является прогнозом held-out leaderboard score.
