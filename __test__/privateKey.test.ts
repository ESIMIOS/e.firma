import { PrivateKey } from '../src/PrivateKey'
import * as fs from 'fs'
const readFile = (fileDir: string) => {
	const pathInvalidCertificate = `${__dirname}/${fileDir}`
	const file = fs.readFileSync(pathInvalidCertificate, 'binary')
	const certiticate = new PrivateKey(file)
	return certiticate
}
describe('privateKey Test', () => {
	test('invalid file', () => {
		const pathInvalidCertificate = `${__dirname}/__data_test__/invalid.der`
		const file = fs.readFileSync(pathInvalidCertificate, 'binary')
		try {
			new PrivateKey(file)
		} catch (err) {
			console.log(err)
			//@ts-ignore
			expect(err.message).toBe('Verifique el archivo, no fue posible decodificar el ANS1')
		}
	})

	test('load decrypted key', () => {
		const pathInvalidCertificate = `${__dirname}/__data_test__/goodPrivateKeyDecrypt.key`
		const file = fs.readFileSync(pathInvalidCertificate, 'binary')
		try {
			new PrivateKey(file)
		} catch (err) {
			console.log(err)
			//@ts-ignore
			expect(err.message.indexOf('Llave privada no válida ') <= 0).toBe(true)
		}
	})
})
