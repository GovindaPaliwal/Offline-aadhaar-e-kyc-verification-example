package com.aadhaar.xmlreader;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;

import in.gov.uidai.auth.aua.httpclient.NamespaceFilter;
import in.gov.uidai.kyc.uid_kyc_response._1.KycRes;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SignatureVerifierOneFile {

	private static String mobilenumber = "Sha256(Sha256(9966528781+1234))*5";
	//private static String mobilenumber = "9966528781";
	private static String mobileXMLEncrypt;

	public static void main(String[] args) throws NoSuchAlgorithmException {
		Security.addProvider(new BouncyCastleProvider());
		// Signed xml path
		String signedXmlPath = "D:/Aadhaar/offlineaadhaar.xml";
		SignatureVerifierOneFile signatureVerifier = new SignatureVerifierOneFile();
		signatureVerifier.verify(signedXmlPath, "D:/Aadhaar/uidai_offline_publickey_19062019.cer");
	}

	public boolean verify(String signedXml, String publicKeyFile) {

		boolean verificationResult = false;

		try {

			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder builder = dbf.newDocumentBuilder();
			Document doc = builder.parse(signedXml);
			NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
			if (nl.getLength() == 0) {
				throw new IllegalArgumentException("Cannot find Signature element");
			}

			XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

			DOMValidateContext valContext = new DOMValidateContext(getCertificateFromFile(publicKeyFile).getPublicKey(),
					nl.item(0));
			XMLSignature signature = fac.unmarshalXMLSignature(valContext);

			verificationResult = signature.validate(valContext);
			System.out.println("xml signature validation is " + verificationResult);

			if (verificationResult) {
				doc = removeSignature(doc);
				String xml = covertDocumentToString(doc);
				//System.out.println("xml--->" + xml);
				//KycRes kycRes1 = (KycRes) parseAuthResponseXML(KycRes.class, xml);
				//System.out.println("kycRes1--->" + kycRes1);
				
				String encryptSHAMob = toHexString(getSHA(mobilenumber));
				/*HashGenerator hashGenerator = new HashGenerator();
				String newMobileNumber = new String(Hex.encode(hashGenerator.generateSha256Hash(mobilenumber.getBytes())));*/
				verifyMobileNumber(doc, encryptSHAMob);
			}

		} catch (Exception e) {
			System.out.println("Error while verifying digital siganature" + e.getMessage());
			e.printStackTrace();
		}

		return verificationResult;
	}

	private void verifyMobileNumber(Document doc, String encryptSHAMob) {
		// TODO Auto-generated method stub
		NodeList nList = doc.getElementsByTagName("Poi");

		//System.out.println("----------------------------");

		for (int temp = 0; temp < nList.getLength(); temp++) {

			Node nNode = nList.item(temp);

			//System.out.println("\nCurrent Element :" + nNode.getNodeName());

			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
				Element eElement = (Element) nNode;

				/*System.out.println("dob : " + eElement.getAttribute("dob"));
				System.out.println("Email : " + eElement.getAttribute("e"));
				System.out.println("gender : " + eElement.getAttribute("gender"));
				System.out.println("Name : " + eElement.getAttribute("name"));
				System.out.println("Mobile : " + eElement.getAttribute("m"));*/
				mobileXMLEncrypt = eElement.getAttribute("m");
			}
		}
		System.out.println("mobileXMLEncrypt--->" + mobileXMLEncrypt);
		System.out.println("encryptSHAMob------>" + encryptSHAMob);
		String SharePhrase = "1234";
		int number = 1;
		// String validNumber = Sha256(Sha256(mobilenumber+SharePhrase))*number;
		if (mobileXMLEncrypt.equals(encryptSHAMob)) {
			System.out.println("---Both Mobiles are Equal--- ");
		} else {
			System.out.println("---Both Mobiles are not Equal--- ");
		}
	}

	private X509Certificate getCertificateFromFile(String certificateFile)
			throws GeneralSecurityException, IOException {
		FileInputStream fis = null;
		try {
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
			fis = new FileInputStream(certificateFile);
			return (X509Certificate) certFactory.generateCertificate(fis);
		} finally {
			if (fis != null) {
				fis.close();
			}
		}
	}

	private static String covertDocumentToString(Document document) throws Exception {
		java.io.StringWriter sw = new java.io.StringWriter();
		try {
			DOMSource domSource = new DOMSource(document);
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();

			transformer.setOutputProperty(OutputKeys.METHOD, "xml");
			StreamResult sr = new StreamResult(sw);
			transformer.transform(domSource, sr);
		} catch (TransformerException e) {
			e.printStackTrace();
		}
		return sw.toString();
	}

	public static Document removeSignature(Document inputDocument) {

		if (inputDocument != null) {
			Element rootElement = inputDocument.getDocumentElement();
			Node n = getSignatureNode(inputDocument);
			if (n != null) {
				rootElement.removeChild(n);
			}
		}
		return inputDocument;
	}

	private static Node getSignatureNode(Document inputDocument) {
		if (inputDocument != null) {
			Element rootElement = inputDocument.getDocumentElement();
			if (rootElement != null) {
				NodeList nl = rootElement.getChildNodes();
				if (nl != null) {
					for (int i = 0; i < nl.getLength(); i++) {
						Node n = nl.item(i);
						if (n != null) {
							if (n.getNodeName() != null && "signature".equalsIgnoreCase(n.getLocalName())) {
								return n;
							}
						}
					}
				}
			}
		}
		return null;
	}

	private static Object parseAuthResponseXML(Class clazz, String xmlToParse) throws JAXBException {
		// Create an XMLReader to use with our filter
		try {
			// Prepare JAXB objects
			JAXBContext jc = JAXBContext.newInstance(clazz);
			Unmarshaller u = jc.createUnmarshaller();

			XMLReader reader;
			reader = XMLReaderFactory.createXMLReader();

			// Create the filter (to add namespace) and set the xmlReader as its
			// parent.
			NamespaceFilter inFilter = new NamespaceFilter(
					"http://www.uidai.gov.in/authentication/uid-auth-response/1.0", true);
			inFilter.setParent(reader);

			// Prepare the input, in this case a java.io.File (output)
			InputSource is = new InputSource(new StringReader(xmlToParse));

			// Create a SAXSource specifying the filter
			SAXSource source = new SAXSource(inFilter, is);

			// Do unmarshalling
			Object res = u.unmarshal(source, clazz).getValue();
			return res;
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}

	public static byte[] getSHA(String input) throws NoSuchAlgorithmException, NoSuchProviderException {
		// Static getInstance method is called with hashing SHA
		MessageDigest md = MessageDigest.getInstance("SHA-256","BC");
		//String salt="1234";
		//md.update(salt.getBytes());

		return md.digest(input.getBytes(StandardCharsets.UTF_8));
	}

	public static String toHexString(byte[] hash) {
		/*// Convert byte array into signum representation
		BigInteger number = new BigInteger(1, hash);

		// Convert message digest into hex value
		StringBuilder hexString = new StringBuilder(number.toString(16));

		// Pad with leading zeros
		while (hexString.length() < 32) {
			hexString.insert(0, '0');
		}*/
		/*StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        System.out.println(sb.toString());

		return sb.toString();*/
		StringBuffer hexString = new StringBuffer();

        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();
        /*String sha256 = DatatypeConverter.printHexBinary(hash).toLowerCase();

        // print SHA-256 Message Digest
        System.out.println(sha256);
        return sha256;*/

	}
}
