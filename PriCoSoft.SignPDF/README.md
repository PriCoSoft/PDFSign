# PDFSign
Assembly version with some optimizations and LTV support

Rewritten but based on https://github.com/IcoDeveloper/PDFSign

#Interface

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
