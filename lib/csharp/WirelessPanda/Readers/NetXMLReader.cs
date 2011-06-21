using System;

namespace WirelessPanda.Readers
{
    // See http://msdn.microsoft.com/en-us/library/cc189056(v=vs.95).aspx
    public class NetXMLReader : Reader
    {
        /// <summary>
        /// Date format (Same format for Kismet CSV and NetXML)
        /// </summary>
        protected override string DATE_FORMAT
        {
            get
            {
                return "ddd MMM dd HH:mm:ss yyyy";
            }
        }

        /// <summary>
        /// Date format (Same format for Kismet CSV and NetXML)
        /// </summary>
        protected override string ALT_DATE_FORMAT
        {
            get
            {
                return "ddd MMM  d HH:mm:ss yyyy";
            }
        }

        /// <summary>
        /// Reader type
        /// </summary>
        public override string ReaderType
        {
            get
            {
                return "Kismet NetXML";
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="filename">Filename (doesn't need to exist now but MUST when using Read() )</param>
        public NetXMLReader(string filename) : base(filename)
        {
            throw new NotImplementedException("NetXML parser not implemented yet");
        }
    }
}
