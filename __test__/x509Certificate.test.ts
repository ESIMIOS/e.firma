import { x509Certificate } from '../src/x509Certificate'
import { PrivateKey } from '../src/PrivateKey'
import * as fs from 'fs'
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
			expect(err.message).toBe('Verifique el archivo, no fue posible decodificar el ANS1')
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
		expect(goodCertiticate.acVersion).toBe(4)
	})
	test('get serialNumber', () => {
		expect(goodCertiticate.serialNumber).toBe('3330303031303030303030343030303032333030')
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

	test('verify Integrity for incorrect issuer', () => {
		const fileIssuer4 = fs.readFileSync(`${__dirname}/__data_test__/AC4_SAT.cer`, 'binary')
		try {
			ipnCertiticate.verifyIntegrity(fileIssuer4)
		} catch (err) {
			expect(err).toBe('El certificado del issuer recibido no es el de este certificado')
		}
	})

	test('verify invalid Integrity', () => {
		const fileIssuer5 = fs.readFileSync(`${__dirname}/__data_test__/AC5_SAT.cer`, 'binary')
		const invalidx509Certificate = readCertificate('__data_test__/00001000000506724016.cer')
		expect(invalidx509Certificate.verifyIntegrity(fileIssuer5)).toBe(false)
	})
})
