import { x509Certificate } from '../src/x509Certificate'
import { PrivateKey } from '../src/PrivateKey'
import * as fs from 'fs'
import ERROR_GENERAL_ERROR from '../src/errors/ERROR_GENERAL_ERROR'
const readCertificate = (fileDir: string) => {
	const pathInvalidCertificate = `${__dirname}/${fileDir}`
	const file = fs.readFileSync(pathInvalidCertificate, 'binary')
	const certiticate = new x509Certificate(file)
	return certiticate
}
describe('x509Certificate Test', () => {
	test('invalid file', () => {
		const pathInvalidCertificate = `${__dirname}/__data_test__/invalid.der`
		const file = fs.readFileSync(pathInvalidCertificate, 'binary')
		try {
			new x509Certificate(file)
		} catch (err) {
			//@ts-ignore
			expect(err.message).toBe('Verifique el archivo, no fue posible decodificar el ASN1')
		}
	})
	test('CSD certificate', () => {
		const csdCertificate = readCertificate('__data_test__/CSD_Certificate.cer')
		expect(csdCertificate.certificateType).toBe('CSD')
	})
	const goodCertiticate = readCertificate('__data_test__/goodCertificate.cer')

	test('EFIRMA certificate', () => {
		expect(goodCertiticate.certificateType).toBe('EFIRMA')
	})

	test('is expired', () => {
		const expired509Certificate = readCertificate('__data_test__/expiredCertificate.cer')
		expect(expired509Certificate.valid).toBe(false)
	})
	test('is valid', () => {
		expect(goodCertiticate.valid).toBe(true)
	})
	test('get acVersion 4', () => {
		expect(goodCertiticate.acVersion).toBe(5)
	})
	test('get serialNumber', () => {
		expect(goodCertiticate.serialNumber).toBe('3330303031303030303030353030303033323832')
	})
	test('encrypted message', () => {
		const message = 'Hola Mundo!'
		const encryptedMessage = goodCertiticate.rsaEncrypt(message)
		const privateKey = new PrivateKey(fs.readFileSync(`${__dirname}/__data_test__/goodPrivateKeyEncrypt.key`, 'binary'))
		const decryptedMessage = privateKey.rsaDecrypt(encryptedMessage, '12345678a')
		expect(message === decryptedMessage).toBe(true)
	})

	test('verify Signature', () => {
		const message = 'Hola Mundo!'
		const privateKey = new PrivateKey(fs.readFileSync(`${__dirname}/__data_test__/goodPrivateKeyEncrypt.key`, 'binary'))
		const signature = privateKey.rsaSign(message, '12345678a')
		const validSignature = goodCertiticate.rsaVerifySignature(message, signature)
		expect(validSignature).toBe(true)
	})

	const ipnCertiticate = readCertificate('__data_test__/ipnCertificate.cer')
	test('get acVersion 5', () => {
		expect(ipnCertiticate.acVersion).toBe(5)
	})

	test('verify Integrity', () => {
		const fileIssuer5 = fs.readFileSync(`${__dirname}/__data_test__/AC5_SAT.cer`, 'binary')
		expect(ipnCertiticate.verifyIntegrity(fileIssuer5)).toBe(true)
	})

	test('verify valid Integrity', () => {
		const fileIssuer5 = fs.readFileSync(`${__dirname}/__data_test__/AC5_SAT.cer`, 'binary')
		expect(ipnCertiticate.verifyIntegrity(fileIssuer5)).toBe(true)
	})

	test('Subject Type', () => {
		expect(ipnCertiticate.subjectType).toBe('MORAL')
		const goodCertiticate = readCertificate('__data_test__/goodCertificate.cer')
		expect(goodCertiticate.subjectType).toBe('FISICA')
	})

	test('verify Integrity for incorrect issuer', () => {
		const fileIssuer4 = fs.readFileSync(`${__dirname}/__data_test__/AC4_SAT.cer`, 'binary')
		try {
			ipnCertiticate.verifyIntegrity(fileIssuer4)
		} catch (err) {
			const error = err as ERROR_GENERAL_ERROR
			expect(error.message).toBe('El certificado recibido no fue emitido por el emisor, verifique que el emisor sea el correcto y que el certificado no este alterado')
		}
	})

	test('verify invalid Integrity', () => {
		const fileIssuer5 = fs.readFileSync(`${__dirname}/__data_test__/AC5_SAT.cer`, 'binary')
		const invalidx509Certificate = readCertificate('__data_test__/00001000000506724016.cer')
		expect(invalidx509Certificate.verifyIntegrity(fileIssuer5)).toBe(false)
	})

	test('getPEM', () => {
		const pem = ipnCertiticate.getPEM().replace(/\r|\n|\t/gm, '')
		const expectedPem = `-----BEGIN CERTIFICATE-----
MIIGWjCCBEKgAwIBAgIUMDAwMDEwMDAwMDA1MTIyMzc4MDQwDQYJKoZIhvcNAQEL
BQAwggGEMSAwHgYDVQQDDBdBVVRPUklEQUQgQ0VSVElGSUNBRE9SQTEuMCwGA1UE
CgwlU0VSVklDSU8gREUgQURNSU5JU1RSQUNJT04gVFJJQlVUQVJJQTEaMBgGA1UE
CwwRU0FULUlFUyBBdXRob3JpdHkxKjAoBgkqhkiG9w0BCQEWG2NvbnRhY3RvLnRl
Y25pY29Ac2F0LmdvYi5teDEmMCQGA1UECQwdQVYuIEhJREFMR08gNzcsIENPTC4g
R1VFUlJFUk8xDjAMBgNVBBEMBTA2MzAwMQswCQYDVQQGEwJNWDEZMBcGA1UECAwQ
Q0lVREFEIERFIE1FWElDTzETMBEGA1UEBwwKQ1VBVUhURU1PQzEVMBMGA1UELRMM
U0FUOTcwNzAxTk4zMVwwWgYJKoZIhvcNAQkCE01yZXNwb25zYWJsZTogQURNSU5J
U1RSQUNJT04gQ0VOVFJBTCBERSBTRVJWSUNJT1MgVFJJQlVUQVJJT1MgQUwgQ09O
VFJJQlVZRU5URTAeFw0yMjA0MDQxODIxMThaFw0yNjA0MDQxODIxNThaMIH2MScw
JQYDVQQDEx5JTlNUSVRVVE8gUE9MSVRFQ05JQ08gTkFDSU9OQUwxJzAlBgNVBCkT
HklOU1RJVFVUTyBQT0xJVEVDTklDTyBOQUNJT05BTDEnMCUGA1UEChMeSU5TVElU
VVRPIFBPTElURUNOSUNPIE5BQ0lPTkFMMQswCQYDVQQGEwJNWDElMCMGCSqGSIb3
DQEJARYWYnV6b250cmlidXRhcmlvQGlwbi5teDElMCMGA1UELRMcSVBOODExMjI5
SDI2IC8gVEFTSjc3MDkzMDhVNTEeMBwGA1UEBRMVIC8gVEFTSjc3MDkzMEhHUlBO
VjA5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgfeCb8bhSrxkhoUS
3Di0BKetdpaETFr5sf8Kqw+peXMZIPZD5QzvJmkZLElE+2JlSYFxrgxH7fHzV9FC
P9rkZ61U+3ekk7d+veenR9Yyj4Gf+AcuMOtKzz2TgQjxZHINFKp4YrqPazxGRYfN
IDwfY+HyIOEgAJnPtCei5+87Ve94x5ySJlsBbvvVAWeTSINraEadyU8ZbLFYL9Zr
h8n+5OZHRuL6As+kSd/nrd0re07AjKP6fISXzx7voR6Y752YCgXvFr6qoErvNvNJ
lEID0lqe74m+k6Iq+leC5Z36vAdXvven4I2CkLE06CXPr6eEQit1uGAn6vkwfPjc
VDkbgwIDAQABo08wTTAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwID2DARBglghkgB
hvhCAQEEBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwQGCCsGAQUFBwMCMA0GCSqG
SIb3DQEBCwUAA4ICAQCl5bBM9Qpr5iHQMmeOh4afi6uSP5edv1cCYXAW11bzNs71
pgmRM721PgKswvDVjOPNhwRrVj9/Vb8yr1FgXC8nktGGDVw1/4AKWvIqj6dwIFTi
vG4NFIEWmvk5bxTK7j8GY2ATuDq+UInoMIm9SrUwby8pQIwat3MmXKPP7iwXYB0G
48wbTGB+uxUjcQNcEk0ti7fO9WqZdg1KW6pCGLWfaRPrRt31ZFkv/WvfejVJSS9D
D7XOZ/5NgY0AdY5JvBLuA3fCcJsNdx3ziR9n1DpFc+3w60T6bR55LaTe9MWWFsaB
C92JR16wucbA3nx/qSyXnVhAOR1tCC6TAxXWEaCMRaeniDCPCUd299ZnSCYE/bGj
5ZjrKjd3/HqjfTHLKyLMaLiz3kWLWdZlCsh3gOszMeNGRP7wWsHyB7qx2MYWSKEE
L3caofydSG3UU2vFDxbzI9Qd8L0DU5sk4KqOrPFpWzxi9V0GbLX7sj+1oDnLL/ar
kNPInxZRy/IBvxr7t3/ToFvuH8W0WV2L0zB6cyEEFmuzU3yEKWl15Jk2tV4GWk7l
1cUyWr8/WGjw/+8eF0KhrEDj9Jhx+34GQJumf5gRUHFPA5M2TVxklqIYUsxGGzsq
jeUEmGRPI4/47YpRCp0Kn0vvtUdwex8Q2gceuz7dM7Y9PHjTrzF5nDHZsYNwZw==
-----END CERTIFICATE-----`.replace(/\r|\n|\t/gm, '')
		console.log('pem', pem)
		expect(pem).toBe(expectedPem.replace(/\s\n\r/im, ''))
	})
})
