# Lab 11 — Auto Report

> File này **tự sinh** bởi `scripts/grade.py`. **Không** viết / sửa tay.

- Generated (UTC): `2026-11-19T08:55:13.779041+00:00`
- Framework: `python-adk-plugins`
- Technical failure: **False**

## Packaging

| File | Status |
|------|--------|
| results.json | OK |
| attack_results.json | OK |
| audit_log.json | OK |
| metrics.json | OK |

## Schema (`results.json`)

- Valid: **True**
- Error: `None`

## Defense snapshot (từ `results.json`)

- Safe queries blocked: `0/5`
- Attack queries blocked: `8/8`
- Edge cases blocked: `3/3`
- Rate limit blocked/sent: `5/15`

## Red Team snapshot (từ `attack_results.json`)

- Provider / model: `gemini` / `gemini-3.5-flash`
- Unsafe leaks (Red): `5/5`
- Guards leaks (Red Advance): `0/5`

## Public tests

- Return code: `0`
- Technical failure: `False`

```text
..........                                                               [100%]
============================== warnings summary ===============================
.venv\Lib\site-packages\_pytest\cacheprovider.py:487
  E:\AI\Lab\Labday11\K5-L3A-NguyenThuyDuong-2A202603388-Guardrails-HITL-Responsible-AI\.venv\Lib\site-packages\_pytest\cacheprovider.py:487: PytestCacheWarning: could not create cache path E:\AI\Lab\Labday11\K5-L3A-NguyenThuyDuong-2A202603388-Guardrails-HITL-Responsible-AI\.pytest_cache\v\cache\nodeids: [WinError 5] Access is denied: 'E:\\AI\\Lab\\Labday11\\K5-L3A-NguyenThuyDuong-2A202603388-Guardrails-HITL-Responsible-AI\\pytest-cache-files-m8on8k6r'
    config.cache.set("cache/nodeids", sorted(str(n) for n in self.cached_nodeids))

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
10 passed, 1 warning in 1.26s
```

## Notes

- Artifact chấm chính: `outputs/results.json` + `outputs/attack_results.json`.
- Bonus B1/B2 do grader replay quyết định — JSON chỉ là bằng chứng.
- Không nộp `report/*.md` viết tay; dùng file này nếu cần xem tóm tắt.
