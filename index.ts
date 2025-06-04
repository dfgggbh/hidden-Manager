import { Hono } from 'hono'
import { z } from 'zod'
import * as YAML from 'yaml'
import OTPAuth from 'otpauth'

const app = new Hono()

app.get('/', (c) => c.text('Umbrix Ultra Manager is Live!'))

app.get('/otp', (c) => {
  const secret = new OTPAuth.Secret({ size: 20 })
  const totp = new OTPAuth.TOTP({
    issuer: 'Umbrix',
    label: 'ultra',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: secret
  })
  return c.text(totp.generate())
})

export default app