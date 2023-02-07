import { Ocsp } from '../src/Ocsp'
import { asn1 } from 'node-forge'
import { x509Certificate } from '../src/x509Certificate'
import * as fs from 'fs'
const readFile = (fileDir: string) => {
	const pathInvalidCertificate = `${__dirname}/${fileDir}`
	const file = fs.readFileSync(pathInvalidCertificate, 'binary')
	return file
}
const readCertificate = (fileDir: string) => {
	const pathInvalidCertificate = `${__dirname}/${fileDir}`
	const file = fs.readFileSync(pathInvalidCertificate, 'binary')
	const certiticate = new x509Certificate(file)
	return certiticate
}
const subjectCertiticate = readCertificate('__data_test__/ipnCertificate.cer')
const ocspCertificate4 = readCertificate('__data_test__/ocsp.ac4_sat.cer')
const ocspCertificate5 = readCertificate('__data_test__/ocsp.ac5_sat.cer')
const issuer5Certificate = readCertificate('__data_test__/AC5_SAT.cer')
describe('OCSP Test', () => {
	test('invalid url ocsp', () => {
		try {
			const ocsp = new Ocsp('cfdi.sat.gob.mx/edofi', issuer5Certificate, subjectCertiticate, ocspCertificate4)
		} catch (err) {
			expect(err).toBe('Revisar la url del servicio OCSP, el formato no es de URL')
		}
	})

	test('verify OCSP', async () => {
		const ocsp = new Ocsp('https://cfdi.sat.gob.mx/edofiel', issuer5Certificate, subjectCertiticate, ocspCertificate5)
		const response = await ocsp.verify()
		console.log('response', response)
		expect(response).toHaveProperty('status', 'GOOD')
		expect.stringContaining(response.ocspRequestBinary)
		expect.stringContaining(response.ocspResponseBinary)
	})

	test('invalid signature', async () => {
		try {
			const ocsp = new Ocsp('https://cfdi.sat.gob.mx/edofiel', issuer5Certificate, subjectCertiticate, ocspCertificate4)
			await ocsp.verify()
		} catch (err) {
			expect(err.indexOf('La firma de la respuesta OCSP no corresponde') >= 0).toBe(true)
		}
	})

	test('call service error', async () => {
		try {
			const ocsp = new Ocsp('https://cfdi.sat.gob.mx/edo', issuer5Certificate, subjectCertiticate, ocspCertificate4)
			await ocsp.verify()
		} catch (err) {
			expect(err.indexOf('Error al consultar el servicio') >= 0).toBe(true)
		}
	})

	test('revoked certificate', async () => {
		const ocsp = new Ocsp('https://cfdi.sat.gob.mx/edo', issuer5Certificate, subjectCertiticate, ocspCertificate4)
		const ocspRevokedResponseFile = fs.readFileSync(`${__dirname}/__data_test__/revoked.der`, 'binary')
		const ocspRevokedResponse = asn1.fromDer(ocspRevokedResponseFile)
		//@ts-ignore
		const asn1OCSPBasic = asn1.fromDer(ocspRevokedResponse.value[1]['value'][0].value[1].value)
		const response = ocsp.verifyCertificateStatus(asn1OCSPBasic)
		expect(response).toEqual({ status: 'REVOKED', revocationTime: new Date('2022-11-01T04:17:03.000Z') })
	})

	test('tryLater ocspRequest', async () => {
		const ocsp = new Ocsp('https://cfdi.sat.gob.mx/edo', issuer5Certificate, subjectCertiticate, ocspCertificate4)
		const ocspRevokedResponseFile = fs.readFileSync(`${__dirname}/__data_test__/tryLater.der`, 'binary')
		const ocspRevokedResponse = asn1.fromDer(ocspRevokedResponseFile)
		const response = ocsp.verifyOcspResponse(ocspRevokedResponse)
		expect(response).toEqual({ status: '03' })
	})
})
