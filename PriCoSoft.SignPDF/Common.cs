using System;
using System.Diagnostics;
using System.Text;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using iTextSharp.text.error_messages;
using Mono.Options;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;

namespace PriCoSoft.SignPDF
{
    [ComVisible(true)]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("D89F14C6-C98C-4BB1-AD68-60A583A2CD7B")]
    public interface ISignPDF 
    {
        X509Certificate Certificate { get; }
        string TimeServerUrl { get; set; }
        void SetCertificateStore(string Thumbprint, string Store = "LocalMachine");
        void SetCertificateFile(string Filename, string Password);
        void SetCertificateFile(Stream File, string Password);
        void AddCertificate(byte[] certificate);
        void AddCertificate(string Filename);
        int Sign(string InputFile, string OutputFile);
        int Sign2(string InputFile, string OutputFile);
    }

    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.None)]
    public class SignPDF: ISignPDF
    {
        private Pkcs12Store KeyStore = null;
        private string KeyAlias = null;

        public static List<X509Certificate> extraCertificates = new List<X509Certificate>();

        public X509Certificate Certificate { 
            get { return KeyStore.GetCertificate(KeyAlias).Certificate; } 
        }
        public string TimeServerUrl { get; set; }
        public void SetCertificateStore(string Thumbprint, string Store = "LocalMachine")
        {
            System.Security.Cryptography.X509Certificates.X509Certificate2 cer = null;
            System.Security.Cryptography.X509Certificates.StoreLocation certStoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine;
            if (Store.Equals("CurrentUser", StringComparison.OrdinalIgnoreCase))
                certStoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser;
            System.Security.Cryptography.X509Certificates.X509Store certStore = new System.Security.Cryptography.X509Certificates.X509Store(certStoreLocation);
            certStore.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);
            System.Security.Cryptography.X509Certificates.X509Certificate2Collection certs = 
                certStore.Certificates.Find(System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint, Thumbprint, false);
            if (certs.Count > 0) { cer = certs[0]; } else { throw new InvalidOperationException("Certificate with specified thumbprint not found"); }
            System.Security.Cryptography.X509Certificates.X509Certificate2Collection certCol = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection();
            System.Security.Cryptography.X509Certificates.X509Chain x509chain = new System.Security.Cryptography.X509Certificates.X509Chain();
            x509chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
            x509chain.Build(cer);
            for (int chainIDX = 0; chainIDX < x509chain.ChainElements.Count; chainIDX++)
                certCol.Add(x509chain.ChainElements[chainIDX].Certificate);            
            byte[] pkcs12 = certCol.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pkcs12, "");
            Stream fs = new MemoryStream(pkcs12);
            try
            {
                fs.Seek(0, SeekOrigin.Begin);
                SetCertificateFile(fs, "");
            } finally { fs.Close(); }
        }
        public void SetCertificateFile(string Filename, string Password)
        {
            Stream fs = new FileStream(Filename, FileMode.Open, FileAccess.Read);
            try
            {
                SetCertificateFile(fs, Password);
            }
            finally { fs.Close(); }            
        }

        public void SetCertificateFile(Stream File, string Password)
        {
            Pkcs12Store ks = new Pkcs12Store(File, Password.ToCharArray());
            string alias = null;
            foreach (string al in ks.Aliases)
            {
                if (ks.IsKeyEntry(al) && ks.GetKey(al).Key.IsPrivate)
                {
                    alias = al;
                    break;
                }
            }
            KeyStore = ks;
            KeyAlias = alias;
        }

        public int Sign(string InputFile, string OutputFile)
        {
            // extracting certifiactes
            ICipherParameters pk = KeyStore.GetKey(KeyAlias).Key;
            X509CertificateEntry[] x = KeyStore.GetCertificateChain(KeyAlias);
            Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[x.Length];
            for (int k = 0; k < x.Length; ++k) { chain[k] = x[k].Certificate; }

            PdfReader reader;
            reader = new PdfReader(InputFile);
            FileStream fout = new FileStream(OutputFile, FileMode.Create, FileAccess.Write);
            PdfStamper stp = PdfStamper.CreateSignature(reader, fout, '\0', null, true);
            PdfSignatureAppearance sap = stp.SignatureAppearance;

            TSAClientBouncyCastle tsa = null;
            if (!string.IsNullOrEmpty(TimeServerUrl))
                tsa = new TSAClientBouncyCastle(TimeServerUrl);

            IExternalSignature es = new PrivateKeySignature(pk, "SHA-256");
            MakeSignature.SignDetached(sap, es, new Org.BouncyCastle.X509.X509Certificate[] { KeyStore.GetCertificate(KeyAlias).Certificate }, null, null, tsa, 0, CryptoStandard.CADES);
            stp.Close();

            return 0;
        }

        public void AddCertificate(byte[] certificate)
        {
            extraCertificates.Add(new Org.BouncyCastle.X509.X509Certificate(X509CertificateStructure.GetInstance(certificate)));
        }

        public void AddCertificate(string Filename)
        {
            System.Security.Cryptography.X509Certificates.X509Certificate2 extra = new System.Security.Cryptography.X509Certificates.X509Certificate2(Filename);
            AddCertificate(extra.GetRawCertData());
        }

        public int Sign2(string InputFile, string OutputFile)
        {
            string tempFile = Path.GetTempFileName();
            try
            {
                int retVal = Sign(InputFile, tempFile);
                if (retVal != 0) {  return retVal; }

                byte[] signedDocument = File.ReadAllBytes(tempFile);
                PdfReader reader = new PdfReader(signedDocument);
                FileStream fout = new FileStream(OutputFile, FileMode.Create);
                PdfStamper pdfStamper = new PdfStamper(reader, fout, '\0', true);
                
                // add extra defined certificates
                AdobeLtvEnabling adobeLtvEnabling = new AdobeLtvEnabling(pdfStamper);
                foreach (var x in extraCertificates) { adobeLtvEnabling.extraCertificates.Add(x); }

                // add complete certificate chain list (of the certificate itself)
                X509CertificateEntry[] c = KeyStore.GetCertificateChain(KeyAlias);
                for (int k = 0; k < c.Length; ++k) 
                    adobeLtvEnabling.extraCertificates.Add(c[k].Certificate);

                // perform LTV operation
                IOcspClient ocsp = new OcspClientBouncyCastle(null);
                ICrlClient crl = new CrlClientOnline();
                adobeLtvEnabling.enable(ocsp, crl);
                pdfStamper.Close();

                return 0;

            }
            finally { 
                if (File.Exists(tempFile)) { 
                    File.Delete(tempFile); 
                } 
            };
        }

    }

    class AdobeLtvEnabling
    {
        PdfStamper pdfStamper;
        ISet<X509Certificate> seenCertificates = new HashSet<X509Certificate>();
        IDictionary<PdfName, ValidationData> validated = new Dictionary<PdfName, ValidationData>();
        
        public List<X509Certificate> extraCertificates = new List<X509Certificate>();

        public AdobeLtvEnabling(PdfStamper pdfStamper)
        {
            this.pdfStamper = pdfStamper;
        }
        public void enable(IOcspClient ocspClient, ICrlClient crlClient)
        {
            AcroFields fields = pdfStamper.AcroFields;
            bool encrypted = pdfStamper.Reader.IsEncrypted();

            List<String> names = fields.GetSignatureNames();
            foreach (String name in names)
            {
                PdfPKCS7 pdfPKCS7 = fields.VerifySignature(name);
                PdfDictionary signatureDictionary = fields.GetSignatureDictionary(name);
                X509Certificate certificate = pdfPKCS7.SigningCertificate;
                addLtvForChain(certificate, ocspClient, crlClient, getSignatureHashKey(signatureDictionary, encrypted));
            }

            outputDss();
        }
        void addLtvForChain(X509Certificate certificate, IOcspClient ocspClient, ICrlClient crlClient, PdfName key)
        {
            if (seenCertificates.Contains(certificate))
                return;
            seenCertificates.Add(certificate);
            ValidationData validationData = new ValidationData();

            while (certificate != null)
            {
                X509Certificate issuer = getIssuerCertificate(certificate);
                validationData.certs.Add(certificate.GetEncoded());
                byte[] ocspResponse = ocspClient.GetEncoded(certificate, issuer, null);
                if (ocspResponse != null)
                {
                    validationData.ocsps.Add(ocspResponse);
                    X509Certificate ocspSigner = getOcspSignerCertificate(ocspResponse);
                    addLtvForChain(ocspSigner, ocspClient, crlClient, getOcspHashKey(ocspResponse));
                }
                else
                {
                    ICollection<byte[]> crl = crlClient.GetEncoded(certificate, null);
                    if (crl != null && crl.Count > 0)
                    {
                        foreach (byte[] crlBytes in crl)
                        {
                            validationData.crls.Add(crlBytes);
                            addLtvForChain(null, ocspClient, crlClient, getCrlHashKey(crlBytes));
                        }
                    }
                }
                certificate = issuer;
            }

            validated[key] = validationData;
        }
        void outputDss()
        {
            PdfWriter writer = pdfStamper.Writer;
            PdfReader reader = pdfStamper.Reader;

            PdfDictionary dss = new PdfDictionary();
            PdfDictionary vrim = new PdfDictionary();
            PdfArray ocsps = new PdfArray();
            PdfArray crls = new PdfArray();
            PdfArray certs = new PdfArray();

            writer.AddDeveloperExtension(PdfDeveloperExtension.ESIC_1_7_EXTENSIONLEVEL5);
            writer.AddDeveloperExtension(new PdfDeveloperExtension(PdfName.ADBE, new PdfName("1.7"), 8));

            PdfDictionary catalog = reader.Catalog;
            pdfStamper.MarkUsed(catalog);
            foreach (PdfName vkey in validated.Keys)
            {
                PdfArray ocsp = new PdfArray();
                PdfArray crl = new PdfArray();
                PdfArray cert = new PdfArray();
                PdfDictionary vri = new PdfDictionary();
                foreach (byte[] b in validated[vkey].crls)
                {
                    PdfStream ps = new PdfStream(b);
                    ps.FlateCompress();
                    PdfIndirectReference iref = writer.AddToBody(ps, false).IndirectReference;
                    crl.Add(iref);
                    crls.Add(iref);
                }
                foreach (byte[] b in validated[vkey].ocsps)
                {
                    PdfStream ps = new PdfStream(buildOCSPResponse(b));
                    ps.FlateCompress();
                    PdfIndirectReference iref = writer.AddToBody(ps, false).IndirectReference;
                    ocsp.Add(iref);
                    ocsps.Add(iref);
                }
                foreach (byte[] b in validated[vkey].certs)
                {
                    PdfStream ps = new PdfStream(b);
                    ps.FlateCompress();
                    PdfIndirectReference iref = writer.AddToBody(ps, false).IndirectReference;
                    cert.Add(iref);
                    certs.Add(iref);
                }
                if (ocsp.Length > 0)
                    vri.Put(PdfName.OCSP, writer.AddToBody(ocsp, false).IndirectReference);
                if (crl.Length > 0)
                    vri.Put(PdfName.CRL, writer.AddToBody(crl, false).IndirectReference);
                if (cert.Length > 0)
                    vri.Put(PdfName.CERT, writer.AddToBody(cert, false).IndirectReference);
                vri.Put(PdfName.TU, new PdfDate());
                vrim.Put(vkey, writer.AddToBody(vri, false).IndirectReference);
            }
            dss.Put(PdfName.VRI, writer.AddToBody(vrim, false).IndirectReference);
            if (ocsps.Length > 0)
                dss.Put(PdfName.OCSPS, writer.AddToBody(ocsps, false).IndirectReference);
            if (crls.Length > 0)
                dss.Put(PdfName.CRLS, writer.AddToBody(crls, false).IndirectReference);
            if (certs.Length > 0)
                dss.Put(PdfName.CERTS, writer.AddToBody(certs, false).IndirectReference);
            catalog.Put(PdfName.DSS, writer.AddToBody(dss, false).IndirectReference);
        }
        static PdfName getCrlHashKey(byte[] crlBytes)
        {
            X509Crl crl = new X509Crl(CertificateList.GetInstance(crlBytes));
            byte[] signatureBytes = crl.GetSignature();
            DerOctetString octetString = new DerOctetString(signatureBytes);
            byte[] octetBytes = octetString.GetEncoded();
            byte[] octetHash = hashBytesSha1(octetBytes);
            PdfName octetName = new PdfName(Utilities.ConvertToHex(octetHash));
            return octetName;
        }
        static PdfName getOcspHashKey(byte[] basicResponseBytes)
        {
            BasicOcspResponse basicResponse = BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(basicResponseBytes));
            byte[] signatureBytes = basicResponse.Signature.GetBytes();
            DerOctetString octetString = new DerOctetString(signatureBytes);
            byte[] octetBytes = octetString.GetEncoded();
            byte[] octetHash = hashBytesSha1(octetBytes);
            PdfName octetName = new PdfName(Utilities.ConvertToHex(octetHash));
            return octetName;
        }
        static PdfName getSignatureHashKey(PdfDictionary dic, bool encrypted)
        {
            PdfString contents = dic.GetAsString(PdfName.CONTENTS);
            byte[] bc = contents.GetOriginalBytes();
            if (PdfName.ETSI_RFC3161.Equals(PdfReader.GetPdfObject(dic.Get(PdfName.SUBFILTER))))
            {
                using (Asn1InputStream din = new Asn1InputStream(bc))
                {
                    Asn1Object pkcs = din.ReadObject();
                    bc = pkcs.GetEncoded();
                }
            }
            byte[] bt = hashBytesSha1(bc);
            return new PdfName(Utilities.ConvertToHex(bt));
        }
        static byte[] hashBytesSha1(byte[] b)
        {
            System.Security.Cryptography.SHA1 sha = new System.Security.Cryptography.SHA1CryptoServiceProvider();
            return sha.ComputeHash(b);
        }
        static X509Certificate getOcspSignerCertificate(byte[] basicResponseBytes)
        {
            BasicOcspResponse borRaw = BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(basicResponseBytes));
            BasicOcspResp bor = new BasicOcspResp(borRaw);

            foreach (X509Certificate x509Certificate in bor.GetCerts())
            {
                if (bor.Verify(x509Certificate.GetPublicKey()))
                    return x509Certificate;
            }

            return null;
        }
        static byte[] buildOCSPResponse(byte[] BasicOCSPResponse)
        {
            DerOctetString doctet = new DerOctetString(BasicOCSPResponse);
            Asn1EncodableVector v2 = new Asn1EncodableVector();
            v2.Add(OcspObjectIdentifiers.PkixOcspBasic);
            v2.Add(doctet);
            DerEnumerated den = new DerEnumerated(0);
            Asn1EncodableVector v3 = new Asn1EncodableVector();
            v3.Add(den);
            v3.Add(new DerTaggedObject(true, 0, new DerSequence(v2)));
            DerSequence seq = new DerSequence(v3);
            return seq.GetEncoded();
        }
        private bool verifySignature(AsymmetricKeyParameter key, X509Certificate certificate)
        {
            // re-write of "certificate.Verify(certificate.GetPublicKey());" to avoid exceptions
            X509CertificateStructure c = certificate.CertificateStructure;
            IVerifierFactory verifier = new Org.BouncyCastle.Crypto.Operators.Asn1VerifierFactory(c.SignatureAlgorithm, key);
            _ = c.SignatureAlgorithm.Parameters;
            IStreamCalculator streamCalculator = verifier.CreateCalculator();
            byte[] tbsCertificate = c.TbsCertificate.GetDerEncoded();
            streamCalculator.Stream.Write(tbsCertificate, 0, tbsCertificate.Length);
            streamCalculator.Stream.Close();
            return ((IVerifier)streamCalculator.GetResult()).IsVerified(c.GetSignatureOctets());
        }
        X509Certificate getIssuerCertificate(X509Certificate certificate)
        {
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;

            String url = getCACURL(certificate);
            if (url != null && url.Length > 0)
            {
                HttpWebRequest con = (HttpWebRequest)WebRequest.Create(url);
                HttpWebResponse response = (HttpWebResponse)con.GetResponse();
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new IOException(MessageLocalization.GetComposedMessage("invalid.http.response.1", (int)response.StatusCode));
                //Get Response
                Stream inp = response.GetResponseStream();
                byte[] buf = new byte[1024];
                MemoryStream bout = new MemoryStream();
                while (true)
                {
                    int n = inp.Read(buf, 0, buf.Length);
                    if (n <= 0)
                        break;
                    bout.Write(buf, 0, n);
                }
                inp.Close();

                var cert2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(bout.ToArray());
                return new X509Certificate(X509CertificateStructure.GetInstance(cert2.GetRawCertData()));
            }

            if (verifySignature(certificate.GetPublicKey(), certificate)) { return null; }
            foreach (X509Certificate candidate in extraCertificates)
            {
                if (verifySignature(candidate.GetPublicKey(), certificate)) 
                { 
                    return candidate; 
                }
            }
            return null;
        }
        static String getCACURL(X509Certificate certificate)
        {
            try
            {
                Asn1Object obj = getExtensionValue(certificate, X509Extensions.AuthorityInfoAccess.Id);
                if (obj == null)
                {
                    return null;
                }

                Asn1Sequence AccessDescriptions = (Asn1Sequence)obj;
                for (int i = 0; i < AccessDescriptions.Count; i++)
                {
                    Asn1Sequence AccessDescription = (Asn1Sequence)AccessDescriptions[i];
                    if (AccessDescription.Count != 2)
                    {
                        continue;
                    }
                    else
                    {
                        if ((AccessDescription[0] is DerObjectIdentifier) && ((DerObjectIdentifier)AccessDescription[0]).Id.Equals("1.3.6.1.5.5.7.48.2"))
                        {
                            String AccessLocation = getStringFromGeneralName((Asn1Object)AccessDescription[1]);
                            return AccessLocation == null ? "" : AccessLocation;
                        }
                    }
                }
            }
            catch { }
            return null;
        }
        static Asn1Object getExtensionValue(X509Certificate certificate, String oid)
        {
            try
            {
                DerObjectIdentifier oidObject = new DerObjectIdentifier(oid);
                Asn1OctetString extensionValue = certificate.GetExtensionValue(oidObject);
                if (extensionValue == null) { return null; }
                byte[] bytes = extensionValue.GetDerEncoded();
                if (bytes == null)
                {
                    return null;
                }
                Asn1InputStream aIn = new Asn1InputStream(new MemoryStream(bytes));
                Asn1OctetString octs = (Asn1OctetString)aIn.ReadObject();
                aIn = new Asn1InputStream(new MemoryStream(octs.GetOctets()));
                return aIn.ReadObject();
            }
            catch { return null; }
        }
        private static String getStringFromGeneralName(Asn1Object names)
        {
            Asn1TaggedObject taggedObject = (Asn1TaggedObject)names;
            return Encoding.GetEncoding(1252).GetString(Asn1OctetString.GetInstance(taggedObject, false).GetOctets());
        }
        class ValidationData
        {
            public IList<byte[]> crls = new List<byte[]>();
            public IList<byte[]> ocsps = new List<byte[]>();
            public IList<byte[]> certs = new List<byte[]>();
        }
    }
}
