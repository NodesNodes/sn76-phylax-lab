export function merge(target, req, name) {
  target[ALLOWED_KEYS[name]] = req.body.value;
}
