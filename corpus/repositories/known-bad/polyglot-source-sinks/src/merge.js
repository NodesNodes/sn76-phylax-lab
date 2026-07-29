export function merge(target, req) {
  target[req.body.key] = req.body.value;
}
