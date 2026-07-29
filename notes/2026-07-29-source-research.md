# 2026-07-29 — source research for the packages and MCP agents

## Контекст

В `agent/` находятся два сабмита для разных треков, но оба используют один
детектор:

| env | хоткей | трек | файл |
|---|---|---|---|
| `.env` | `sn76` | `packages` | `agent/phylax_agent.py` |
| `.env.mcp` | `sn76_1` | `mcp_servers` | `agent/phylax_agent.py` |

Выбор env-файла выполняется через `PHYLAX_ENV_FILE`, а `agent_main` ветвится по
треку. Поэтому источники оценивались не как два независимых списка сигнатур, а
как материал для общего анализатора с track-specific логикой.

Выводы по GitHub-источникам получены в этом ресерче независимо. Заметка
`2026-07-29-agent-v3.md`, подготовленная Claude Code, используется только как
дополнительное подтверждение регрессии, но не как источник направлений или
сигнатур. Критерием ценности изменения был validator-first цикл:

1. извлечь из источника конкретную форму атаки или честный контрпример;
2. добавить malicious-case и максимально близкий benign twin;
3. внести узкое структурное правило;
4. сравнить validator до и после на одной и той же расширенной выборке;
5. сохранить изменение только при улучшении score без новых false positive.

GitHub-репозиторий сам по себе не считался доказательством вредоносности.
Сигналы переносились только как структуры данных, пути потока или формы
регистрации инструмента.

## Коррекция направления после сверки с `agent-v3`

`agent-v3` в основном исследует `skills` и частично `repositories`:
extension-less scripts, prompt injection в CSV, дедупликацию findings и
особенности repository evaluator. Для текущей задачи это неверное направление:
сабмиты `sn76` и `sn76_1` относятся только к `packages` и `mcp_servers`.

Поэтому из `agent-v3` не переносим:

- изменения и новые артефакты трека `skills`;
- направление по `repositories` и обсуждение его heuristic ceiling;
- идею подстраиваться под ошибку evaluator-а с помощью вымышленных findings;
- изменение `corpus/packages/known-bad/env-spread/label.json` как доказательство
  улучшения детектора.

Последний пункт особенно важен: сам `agent-v3` прямо отмечает, что изменение
label сдвинуло packages score без изменения кода и является предположением о
held-out разметке. Это можно хранить как corpus-consistency заметку, но нельзя
засчитывать как validator-backed улучшение агента.

Из `agent-v3` принимаем только относящиеся к нашим двум трекам регрессионные
факты:

| Проверка | Подтверждено в `agent-v3` |
|---|---|
| Public packages | `1.000` |
| Local packages corpus | `1.000`, 20 артефактов |
| Public MCP servers | `1.000` |
| Local MCP corpus | `1.000`, 17 артефактов |
| Rulecheck | 14/14 |
| Fuzz | 88/88, без crashes и degraded fallbacks |

Все source-specific A/B ниже относятся к отдельному расширенному
`harness/trackcheck.py`, а не к skills/repositories работе из `agent-v3`.

## Итоговое состояние

- SHA-256 `agent/phylax_agent.py`:
  `3b406c9879f7e4268d69e4e66ad14033cebe10fb5bb882f1bac21fa54b6bee03`
- Размер: 3277 строк, 150193 байта.
- Expanded packages validator: `1.0000`, TP 17, TN 11, FP 0, FN 0,
  MCC 1.0, quality 1.0.
- Expanded MCP validator: `1.0000`, TP 17, TN 18, FP 0, FN 0,
  MCC 1.0, quality 1.0.
- Public upstream corpora: `1.0000` на обоих треках.
- Existing local corpora: packages 20/20, MCP 17/17.
- Rulecheck: 14/14.
- Fuzz: 88 dispatches, 0 problems.
- Sandbox preflight: imports, return contract и determinism пройдены.

Это локальная validator-compatible верхняя граница, а не фактический held-out
leaderboard score. Оба агента после проверки были отправлены; детали приведены
в разделе `Submission status`. Held-out score на момент записи ещё неизвестен.

## Источники, которые дали прямые изменения

### [Tencent AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)

Самый полезный источник для `mcp_servers`. В его MCP-наборе есть отдельные
кейсы для command injection, credential exfiltration, excessive permissions,
missing auth, path traversal, prompt injection через результаты tools и
resources, SQL injection, SSRF, unsafe deserialization, tool poisoning и
tool rug-pull.

Особенно полезными оказались реальные формы:

- tool-параметр достигает `eval`, `exec`, `os.system` или shell subprocess;
- tool читает credential-файлы и отправляет содержимое наружу;
- после регистрации меняется `function.__doc__`, то есть описание инструмента
  может стать другим уже после проверки;
- `tools/list` или аналогичный удалённый источник способен вернуть новую
  семантику инструмента;
- небезопасная десериализация вызывается на пользовательском tool-input.

На их основе добавлены:

- Python- и JS/TS-taint от tool-параметров к shell/eval sink;
- unsafe-deserialization detection с учётом источника данных;
- remote `tools/list` rug-pull detection;
- post-registration mutation `function.__doc__`;
- точные категории `rug_pull` и `permission_overreach`.

Не были добавлены правила вида «любой URL = SSRF» или «любой внешний ответ
вредоносен». Честные weather/search/fetch tools делают такие правила слишком
шумными. Для блокировки требуется связь между недоверенным вводом, опасным
sink и отсутствием достаточного ограничения.

### [Shannon](https://github.com/KeygraphHQ/shannon)

Реальный TypeScript-код использует factory-object форму:

```ts
defineTool({
  name: "...",
  description: "...",
  parameters: ...,
  execute: ...
})
```

Это выявило пробел парсера: анализ только декораторов и прямых конструкторов не
восстанавливал поверхность таких tools. Добавлен разбор JS/TS object factories,
включая вложенные descriptions и parameters.

Контроль: реальные Shannon session tools остаются `ALLOW`; имена `glob` и
`todo_write` успешно восстанавливаются.

### [Metasploit Framework](https://github.com/rapid7/metasploit-framework)

Неожиданно полезный источник реального Ruby MCP DSL. В `msfmcpd` встречаются:

```ruby
class SomeTool < ::MCP::Tool
  tool_name "..."
  description <<~DESC
    ...
  DESC
  input_schema(...)
end
```

Добавлен Ruby surface parser для `MCP::Tool`, `tool_name`, многострочных
description и input schema.

Источник также стал важным benign-контрпримером: слова `exploit`,
`credential`, `payload`, `module` и offensive-security назначение сами по себе
не означают malicious MCP server. Реальные tools
`msf_credential_info`, `msf_module_info` и `msf_search_modules`
восстанавливаются и получают `ALLOW`.

### [Deepfence SecretScanner](https://github.com/deepfence/SecretScanner)

Репозиторий содержит большой каталог типов секретов и тем самым показывает,
что простое упоминание `token`, `password`, `private key` или cloud credential
может быть нормальной функцией scanner-а.

Из источника взяты не ключевые слова, а дополнительные конкретные
credential-paths, которые становятся сигналом только при фактическом чтении и
дальнейшем опасном использовании:

- `~/.gnupg`;
- Firefox `logins.json`, `key4.db`, `cookies.sqlite`;
- `/etc/shadow`;
- `~/.password-store`;
- service-account и credentials JSON;
- kubeconfig.

Каталог сигнатур и reporting API остаются `ALLOW`; чтение реального секрета с
egress или передачей в нежелательный sink — `BLOCK`.

### [npm security best practices](https://github.com/bodadotsh/npm-security-best-practices)

Источник подтвердил значимость npm lifecycle scripts и supply-chain червей,
которые редактируют `package.json`, добавляют `postinstall` и запускают
локальный payload.

Добавлено распознавание runtime-модификации lifecycle hooks, но только когда
новый hook приводит к опасному локальному payload. Обычный генератор manifest,
build scaffolding и легитимная настройка scripts не блокируются.

### [Capstone](https://github.com/capstone-engine/capstone)

Реальный `setup.py` Capstone использует custom `build_py` и запускает CMake
через `os.system`. Это важный packages benign twin: subprocess в install/build
hook не всегда означает вредоносный postinstall.

Добавлено узкое исключение для native build orchestration. Оно не действует,
если рядом есть download-and-execute, чтение секретов, egress, obfuscation,
shell pipeline, reverse shell или defense evasion.

Контроль: реальный Capstone `setup.py` получает `ALLOW`.

### [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)

Источник дал две дополнительные формы MCP surface:

- собственный bare decorator `@tool`;
- `typing.Annotated[T, "plain string metadata"]`.

Парсер расширен на строковые metadata в `Annotated`, после чего они также
проходят poison-анализ. Реальный исходник остаётся `ALLOW`.

### [Trail of Bits skills](https://github.com/trailofbits/skills)

Supply-chain/YARA-примеры подтвердили, что надёжный детектор должен использовать
составные индикаторы, а не одиночные слова.

Изменения:

- wallet-drainer сигнал требует несколько ERC-20 selectors и JS-контекст;
- сочетание zero-width characters с code execution стало отдельным составным
  сигналом;
- общие wallet-термины были сужены, чтобы не блокировать честные crypto-tools.

### [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)

Источник использован для классов атак на skill/tool descriptions:

- bidi control characters;
- homoglyphs в именах tools;
- shadowing и визуальная подмена известных tools.

При этом наличие Unicode само по себе не блокируется: нужен управляющий или
confusable-паттерн в контексте имени/описания инструмента.

### [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)

Полезен прежде всего как корпус честных security-skills и источник близких
benign twins. Прямые сигнатуры из него не переносились. Его роль — удерживать
правила от блокировки skill только за offensive-security терминологию.

## Источники, использованные как benign-контрпримеры

| Источник | Что проверялось |
|---|---|
| [Prowler](https://github.com/prowler-cloud/prowler) | Cloud API, credentials и subprocess являются нормальными для security scanner-а. |
| [Trivy](https://github.com/aquasecurity/trivy) | Package/container scanning и работа с vulnerability data не должны выглядеть как credential theft. |
| [OWASP Amass](https://github.com/owasp-amass/amass) | DNS, HTTP и asset discovery — честная интенсивная сеть. |
| [subfinder](https://github.com/projectdiscovery/subfinder) | API keys и внешние providers допустимы при соответствии назначению. |
| [ZAP](https://github.com/zaproxy/zaproxy) | Proxying, active scan и отправка crafted requests сами по себе не malicious package behavior. |
| [CrowdSec](https://github.com/crowdsecurity/crowdsec) | Defense tooling может читать логи, запускать remediation и содержать attack taxonomy. |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) | Agentic pentest orchestration и process execution требуют taint-to-sink анализа, а не keyword ban. |
| [DeepAudit](https://github.com/lintsinghua/DeepAudit) | Audit/SAST/PoC verification поддерживают AST/taint подход, но преимущественно относятся к repositories track. |
| [Mirror-Flowers](https://github.com/Ky0toFu/Mirror-Flowers) | Line-level taint, AST и validation полезны методологически; прямых packages/MCP правил мало. |
| [boofuzz](https://github.com/jtpereyda/boofuzz) | Fuzzing, sockets и malformed inputs — честная функция инструмента. |
| [MS-RPC-Fuzzer](https://github.com/warpnet/MS-RPC-Fuzzer) | RPC/network fuzzing не должно блокироваться только по offensive primitives. |
| [LiteBox](https://github.com/microsoft/litebox) | Native execution и sandbox/process management могут быть легитимной инфраструктурой. |

Основной вывод из этой группы: capability не равна intent. Сеть, subprocess,
credential access, exploit vocabulary или генерация payload становятся
сильными сигналами только в конкретной цепочке данных и в противоречии с
заявленной функцией артефакта.

## Источники, не превращённые в правила

### DAST и payload corpora

- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates)
- [Exploitarium](https://github.com/bikini/exploitarium)

Они полезны как будущий malicious corpus, но многие templates доказывают
уязвимость по runtime response, status, matcher или out-of-band callback.
Статический packages/MCP validator такого доказательства не имеет. Перенос
одних payload-строк дал бы много false positive. Использовать их стоит только
с парным benign twin и статически наблюдаемой exploit-цепочкой.

### Offensive collections и evasion

- [BypassAV](https://github.com/matro7sh/BypassAV)
- [RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools)
- [DllShimmer](https://github.com/Print3M/DllShimmer)
- [Pompem](https://github.com/rfunix/Pompem)
- [PentAGI](https://github.com/vxcontrol/pentagi)
- [HackingTool](https://github.com/Z4nzu/hackingtool)

Эти источники дают идеи для атак и тестовых данных, но их низкоуровневые
примитивы пересекаются с легитимными security/native tools. DLL forwarding,
shellcode vocabulary, exploit lookup и AV terminology не были превращены в
самостоятельные блокирующие сигнатуры.

### Справочники и агрегаторы

- [The Book of Secret Knowledge](https://github.com/trimstray/the-book-of-secret-knowledge)
- [Personal Security Checklist](https://github.com/lissy93/personal-security-checklist)
- [BlueTeam-Tools](https://github.com/A-poc/BlueTeam-Tools)

Хороши для taxonomy и ручного ресерча, но недостаточно близки к формату
packages/MCP артефактов. Прямого validator delta не дали.

### Нерелевантный benchmark

[SnitchBench](https://github.com/T3-Content/SnitchBench) проверяет склонность
модели сообщать о действиях пользователя внешним организациям. Это не
supply-chain, malware или MCP benchmark, поэтому в правила и corpus не
переносился.

## Validator A/B

Каждое сравнение ниже выполнено на наборе, уже расширенном кейсами
соответствующей волны. Поэтому значения разных строк нельзя сравнивать между
собой как одну временную серию: менялся сам тестовый набор.

| Волна | Snapshot до | packages после | MCP после | Основной закрытый пробел |
|---|---:|---:|---:|---|
| AI-Infra-Guard | MCP `0.6633` — TP 10, TN 17, FN 6 | `1.0000` | `1.0000` | taint-to-sink, deserialization, rug-pull, doc mutation |
| Secret paths + npm lifecycle + Ruby MCP | packages `0.8696` — TP 15, TN 11, FN 2; MCP `0.9433` — TP 16, TN 18, FN 1 | `1.0000` | `1.0000` | credential path chain, runtime postinstall worm, Ruby surface |

Последний сохранённый pre-wave snapshot:
`/tmp/phylax_agent.before-secret-paths.py`,
SHA-256 `56032de...`.

Главный результат A/B — не само достижение `1.0000`, а отсутствие FP после
добавления структурных позитивов. Для held-out это важнее, чем увеличение числа
широких сигнатур.

## Real-source smoke tests

| Реальный источник | Ожидаемый результат | Результат |
|---|---|---|
| Capstone `setup.py` | ALLOW | ALLOW |
| ida-pro-mcp source | ALLOW | ALLOW |
| AI-Infra-Guard MCP testcase | BLOCK | BLOCK: `tool_poisoning`, `rug_pull`, `permission_overreach`, `overreach` |
| Shannon session tools | ALLOW + surface recovery | ALLOW; `glob`, `todo_write` восстановлены |
| Metasploit Ruby MCP files | ALLOW + surface recovery | ALLOW; три `msf_*` tool восстановлены |

## Что сохранить на следующую сессию

1. Не добавлять raw keyword rules для `eval`, `subprocess`, `credential`,
   `exploit`, `wallet`, URL или security terminology.
2. Каждый новый positive-case сопровождать структурно близким benign twin.
3. Для MCP продолжать приоритет surface recovery: сначала корректно извлечь
   name, description, parameters и handler, затем оценивать intent.
4. Для command injection, secret theft и SSRF требовать наблюдаемую цепочку
   source → transform → sink либо очень специфический составной индикатор.
5. Не считать untrusted tool output автоматически malicious: weather, search,
   fetch и proxy tools легитимно возвращают внешний контент.
6. Для packages отличать install-time выполнение от честного native build;
   опасность создаёт сочетание lifecycle hook с download/secret/egress/
   obfuscation/evasion.
7. Новые источники сначала использовать для corpus и контрпримеров. Правило
   добавлять только после измеримого validator delta.
8. Перед сабмитом повторить public corpus, expanded trackcheck, rulecheck,
   fuzz, sandbox preflight и проверить SHA обоих env-вариантов.
9. Для уже активных packages/MCP v1 не смешивать изменения других треков с
   ресабмитом. `skills` и `repositories` теперь имеют отдельные prepared
   профили и развиваются только под будущие отдельные хоткеи.

## Дополнение: source pass для prepared skills/repositories

После подготовки `.env.skills` и `.env.repositories` пользователь отдельно
разрешил улучшить два будущих профиля. Исторические выводы выше про
packages/MCP сохранены; новые правила не считаются улучшением уже активных v1.

Прямо использованы:

- [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector): persistent
  memory poisoning, HTML-comment concealment, bidi, Unicode Tags/ASCII
  smuggling и emoji-aware benign exceptions;
- [Trail of Bits skills](https://github.com/trailofbits/skills) и
  [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills):
  892 реальных `SKILL.md` как precision controls;
- [Mirror-Flowers](https://github.com/Ky0toFu/Mirror-Flowers): подтверждение
  polyglot repository-аудита для PHP, Java и JavaScript;
- [Trivy](https://github.com/aquasecurity/trivy) и
  [Deepfence SecretScanner](https://github.com/deepfence/SecretScanner):
  точные provider-secret формы и необходимость сканировать не только source
  code, но и другие committed files.

Validator A/B на добавленных twins:

| Проверка | Предыдущий candidate | Новый candidate |
|---|---:|---:|
| Skills source trackcheck | 0.0000 | 1.0000 |
| Repositories expanded, 9 artifacts | 0.6654 | 0.8285 |
| Polyglot malicious source/sink twin | 0.0000 | 1.0000 |
| Polyglot benign source/sink twin | 0.182 | 0.650 |

Реальный skills smoke-test не изменил ни одного решения:
`753 ALLOW / 55 WARN / 84 BLOCK` до и после. Public corpora всех четырёх
треков остались без регрессии; rulecheck расширен с 14 до 22 пар.

Новый working SHA-256:
`1218328472b684f6af08d8c041dde36455f6258de51257efc354aa9a5e6b0db7`.
Он закреплён только за prepared-профилями skills/repositories. Активные
packages/MCP v1 остаются на submitted SHA
`3b406c9879f7e4268d69e4e66ad14033cebe10fb5bb882f1bac21fa54b6bee03`.

## Второй source pass по skills

Повторное чтение правил и официальных SSD fixtures NVIDIA SkillSpector
подтвердило ещё девять false-negative форм: conversation-context egress,
трансформированное извлечение system prompt, base64-hidden instructions,
remote authoritative instructions, semantic constraint demotion,
unrestricted persona, privileged-mode narrative, sensitive-value reflection и
прямое выполнение model output.

Старый кандидат на расширенном skills trackcheck получил `0.3858`
(`TP 4 / TN 12 / FN 9`), новый — `1.0000`
(`TP 13 / TN 12 / FN 0`). Четыре malicious SSD fixture изменились с `ALLOW`
на `WARN`, официальный clean fixture остался `ALLOW`.

Первый вариант sensitive-reflection правила изменял решения четырёх честных
security-skills и был отклонён. После сужения до явного `echo/repeat back` или
включения секретов в каждый ответ полный smoke на 892 реальных skills снова
дал нулевой delta и прежнее распределение
`753 ALLOW / 55 WARN / 84 BLOCK`.

Итоговый working SHA-256:
`41af77c111ebadfe3cf31c992139c4744bc0dc002948344b15330b8a965dedbb`.
Подробный журнал и список намеренно исключённых широких направлений:
[2026-07-29-skills-wave2.md](2026-07-29-skills-wave2.md).

## Submission status

Оба агента отправлены 2026-07-29 с одинаковым кодом, SHA-256
`3b406c9879f7e4268d69e4e66ad14033cebe10fb5bb882f1bac21fa54b6bee03`:

| env | хоткей | SS58 | трек | имя | version | status | agent ID |
|---|---|---|---|---|---:|---|---|
| `.env` | `sn76` | `5HgUJ5SFRRBqbgM84wiZhqeqJhCCC5Au1bXFipjXKCRM8WtL` | `packages` | `phylax-packages-v1` | 1 | active | `5e2c55cf27df4d7581eefe39bff2dc1e` |
| `.env.mcp` | `sn76_1` | `5CqUmyMGijcuqK2iNdnNimdGaVi2jMRoHypz1EoaREPNvygN` | `mcp_servers` | `phylax-mcp-v1` | 1 | active | `c269002145164fd1836e51c039d43df7` |

Оба запроса `/v1/specialization/register` и `/v1/specialization/agent`
вернули `200 OK`. Фактический held-out score пока неизвестен.

### Имена и env

Имена задаются через `PHYLAX_MINER_LABEL`:

```text
.env:     PHYLAX_MINER_LABEL=phylax-packages-v1
.env.mcp: PHYLAX_MINER_LABEL=phylax-mcp-v1
```

`sn76` и `sn76_1` — локальные имена wallet hotkeys, а не публичные имена
агентов. `phylax_agent.py` — имя загружаемого файла. В API публичное поле
`name` получает именно значение `PHYLAX_MINER_LABEL`.

### Execution API key

Ключ намеренно сохранён в обоих env-файлах. Официальный
`scripts/register_miner.py`:

1. требует непустой `PHYLAX_EXECUTION_API_KEY`;
2. принимает только поддерживаемый prefix ключа;
3. завершает работу до POST, если ключ отсутствует;
4. передаёт значение в поле `execution_api_key` запроса
   `/v1/specialization/agent`.

Поэтому вариант сабмита без ключа не использовался и ключ из env не удалялся.
Само секретное значение в заметку не копируется.

### Команды

Packages:

```bash
bash scripts/submit.sh -y
```

MCP servers:

```bash
env PHYLAX_ENV_FILE=/root/labs/sn76-phylax-lab/.env.mcp \
  bash scripts/submit.sh -y
```

`PHYLAX_ENV_FILE` нужен только второму вызову: без него `submit.sh` по
умолчанию читает `.env` и повторно отправил бы packages-вариант.

### Preflight перед отправкой

Оба запуска `submit.sh` независимо выполнили sandbox preflight:

- sandbox Python 3.11.15 импортировал агент;
- `agent_main` вернул валидный report;
- результат был детерминирован в трёх повторениях;
- оба preflight завершились `passed`.

На отправку ушёл один и тот же файл `agent/phylax_agent.py`: 150193 байта на
диске, entrypoint `agent_main`. Сервер для обоих вариантов подтвердил один
`code_sha256`, поэтому packages и MCP действительно используют идентичный
снимок кода.

### Ответы сервера

Packages:

- registration label: `phylax-packages-v1`;
- registration updated at: `2026-07-29T06:37:01.102356Z`;
- agent created at: `2026-07-29T06:37:01.243173`;
- inference provider: `openrouter`;
- inference model: пустое значение;
- agent version: 1;
- status: `active`.

MCP servers:

- registration label: `phylax-mcp-v1`;
- registration created/updated at: `2026-07-29T06:37:16.691845Z`;
- agent created at: `2026-07-29T06:37:16.856748`;
- inference provider: `openrouter`;
- inference model: пустое значение;
- agent version: 1;
- status: `active`.

`active` означает, что сервер принял и активировал загруженную версию. Это не
означает, что held-out evaluation уже завершена.
