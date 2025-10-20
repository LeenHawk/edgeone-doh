export const onRequest = async () => {
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'content-type': 'application/json; charset=utf-8' },
  })
}

