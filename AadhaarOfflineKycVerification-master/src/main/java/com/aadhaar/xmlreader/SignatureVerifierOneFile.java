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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 
 * @author gpfreetech
 */
public class SignatureVerifierOneFile {

	private static String mobilenumber = "XXXXXXXXXX"; // your inputed mobile number
        private static String email = "abcdac@gmail.com"; // your inputed mobile number
        private static String sharePhase = "1234"; // this is your zip file password
	private static String mobileXMLEncrypt; // fetch from xml
        private static String emailXMLEncrypt; // fetch from xml
        private static String LOOP_NUMBER="7"; // last number of your aadhaar card which is 4 number in ref-No
        
        // this is your offline xml path
        private static String signedXmlPath = "C:/Users/USER/Desktop/AadhaarOfflineKycVerification-master/offlineaadhaar.xml";
        // this is your certificate path. make sure you have updated certificate.
        private static String certificatePath = "C:/Users/USER/Desktop/AadhaarOfflineKycVerification-master/uidai_offline_publickey_19062019.cer";
        
        
	public static void main(String[] args) throws NoSuchAlgorithmException {
		Security.addProvider(new BouncyCastleProvider());
		// Signed xml path
		
		SignatureVerifierOneFile signatureVerifier = new SignatureVerifierOneFile();
		signatureVerifier.verify(signedXmlPath, certificatePath);
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
				
				// Called this method is you want to verify user with mobile and email
				verifyUsersDetails(doc);
			}

		} catch (Exception e) {
			System.out.println("Error while verifying digital siganature" + e.getMessage());
			e.printStackTrace();
		}

		return verificationResult;
	}

	private void verifyUsersDetails(Document doc) {
		// TODO Auto-generated method stub
		NodeList nList = doc.getElementsByTagName("Poi");

		for (int temp = 0; temp < nList.getLength(); temp++) {

			Node nNode = nList.item(temp);

			//System.out.println("\nCurrent Element :" + nNode.getNodeName());

			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
				Element eElement = (Element) nNode;

				/* You can print your data
                                System.out.println("dob : " + eElement.getAttribute("dob"));
				System.out.println("Email : " + eElement.getAttribute("e"));
				System.out.println("gender : " + eElement.getAttribute("gender"));
				System.out.println("Name : " + eElement.getAttribute("name"));
				System.out.println("Mobile : " + eElement.getAttribute("m"));*/
				mobileXMLEncrypt = eElement.getAttribute("m");
                                emailXMLEncrypt = eElement.getAttribute("e");
			}
		}
		
		System.out.println("Mobile " );
                mobileAndEmailVerify(mobilenumber, sharePhase, LOOP_NUMBER, mobileXMLEncrypt);
                
                System.out.println("email " );
                mobileAndEmailVerify(email, sharePhase, LOOP_NUMBER, emailXMLEncrypt);
		
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

	public static byte[] getSHA(String input) throws NoSuchAlgorithmException, NoSuchProviderException {
		// Static getInstance method is called with hashing SHA
		MessageDigest md = MessageDigest.getInstance("SHA-256","BC");
		return md.digest(input.getBytes(StandardCharsets.UTF_8));
	}

	public static String toHexString(byte[] hash) {
        // Convert byte array into signum representation  
        BigInteger number = new BigInteger(1, hash);  
  
        // Convert message digest into hex value  
        StringBuilder hexString = new StringBuilder(number.toString(16));  
  
        // Pad with leading zeros 
        while (hexString.length() < 32)  
        {  
            hexString.insert(0, '0');  
        }  
  
        return hexString.toString();  

	}
        
        /**
         * Used same method for both email and mobile number verify
         * @param input_value
         * @param shareCode
         * @param laadhaar
         * @param encodeValue
         * @return 
         */
        private boolean mobileAndEmailVerify(String input_value,String shareCode,String laadhaar,String encodeValue)
        {
            input_value=input_value+shareCode;
            int loop_value=1;
            if(laadhaar.equals("0"))
            {
                laadhaar="1";
                loop_value=1;
            }else{
                loop_value=Integer.valueOf(laadhaar);
            }
            for (int i = 0; i < loop_value; i++) {
                try {
                    input_value=toHexString(getSHA(input_value));
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(SignatureVerifierOneFile.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchProviderException ex) {
                    Logger.getLogger(SignatureVerifierOneFile.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            
            
            System.out.println("---> encoded value  " + encodeValue);
            System.out.println("---> input value    " + input_value);
            
            if(encodeValue.equals(input_value)){
                System.out.println("Verify---> Match" );
                return true;
            }else{
                System.out.println("Verify---> Not Match" );
                return false;
            }
        }
        
        /**
         * Not in used
         * @param clazz
         * @param xmlToParse
         * @return
         * @throws JAXBException 
         */
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
}
