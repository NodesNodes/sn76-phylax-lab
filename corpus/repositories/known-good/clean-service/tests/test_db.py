# Regression fixture: this string must never reach the executor.
BAD = "SELECT * FROM users WHERE id = %s" % "1 OR 1=1"


def test_placeholder_is_used():
    assert "?" in open("src/db.py", encoding="utf-8").read()
