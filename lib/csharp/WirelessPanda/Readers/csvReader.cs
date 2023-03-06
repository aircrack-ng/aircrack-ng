// License: BSD/LGPL
// Copyright (C) 2011-2018 Thomas d'Otreppe
using System;
using System.Collections.Generic;

namespace WirelessPanda.Readers
{
    public class CsvReader : Reader
    {
        /// <summary>
        /// Date format (Same format for 0.x and 1.x)
        /// </summary>
        protected override string DATE_FORMAT
        {
            get
            {
                return "yyyy-MM-dd HH:mm:ss";
            }
        }

        public enum CSVFileFormat
        {
            v0X,
            v1X,
            Unknown
        }

        /// <summary>
        /// Get the file format
        /// </summary>
        public CSVFileFormat FileFormat
        {
            get
            {
                return this._fileFormat;
            }
        }

        private CSVFileFormat _fileFormat = CSVFileFormat.Unknown;

        /// <summary>
        /// Reader type
        /// </summary>
        public override string ReaderType
        {
            get
            {
                return "Airodump-ng CSV";
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="filename">Filename (doesn't need to exist now but MUST when using Read() )</param>
        public CsvReader(string filename) : base(filename) { }

        /// <summary>
        /// Read/Update the content of the file
        /// </summary>
        /// <returns>true if successful</returns>
        /// <exception cref="FormatException">Airodump-ng CSV format unknown</exception>
        public override bool Read()
        {
            // Reset parsing status
            this.ParseSuccess = false;

            // Get the content of the file
            string[] content = this.getStrippedFileContent();

            // Get file format
            this._fileFormat = this.getFormat(content);

            if (this._fileFormat == CSVFileFormat.Unknown)
            {
                throw new FormatException("Airodump-ng CSV format unknown");
            }

            // Parse AP ...
            int i = 2; // Start at line 3 (skipping header)
            for (; i < content.Length && !string.IsNullOrEmpty(content[i]); i++) 
            {
                string [] split = content[i].Split(',');

                switch (this._fileFormat)
                {
                    case CSVFileFormat.v0X:
                        if (split.Length < 11)
                        {
                            continue;
                        }
                        break;

                    case CSVFileFormat.v1X:
                        if (split.Length < 15)
                        {
                            continue;
                        }
                        break;
                }
                AccessPoint ap = new AccessPoint();
                ap.BSSID = split[0].Trim();
                ap.FirstTimeSeen = this.parseDateTime(split[1]);
                ap.LastTimeSeen = this.parseDateTime(split[2]);
                ap.Channel = int.Parse(split[3].Trim());
                ap.MaxRate = double.Parse(split[4].Trim());
                ap.Privacy = split[5].Trim();

                switch (this._fileFormat)
                {
                    case CSVFileFormat.v0X:
                        ap.Power = int.Parse(split[6].Trim());
                        ap.Beacons = long.Parse(split[7].Trim());
                        ap.DataFrames = ulong.Parse(split[8].Trim());
                        ap.IP = split[9].Replace(" ", "");
                        ap.ESSID = split[10].Substring(1); // TODO: Improve it because it may contain a ','
                        ap.ESSIDLength = (byte)ap.ESSID.Length;
                        break;

                    case CSVFileFormat.v1X:
                        ap.Cipher = split[6].Trim();
                        ap.Authentication = split[7].Trim();
                        ap.Power = int.Parse(split[8].Trim());
                        ap.Beacons = long.Parse(split[9].Trim());
                        ap.DataFrames = ulong.Parse(split[10].Trim());
                        ap.IP = split[11].Replace(" ", "");
                        ap.ESSIDLength = byte.Parse(split[12].Trim());
                        ap.ESSID = split[13].Substring(1); // TODO: Improve it because it may contain a ','
                        ap.Key = split[14];
                        break;
                }

                // Add AP to the list
                this.addAccessPoint(ap);
            }

            // ... Parse stations

            i += 2; // Skip station header
            for (; i < content.Length && !string.IsNullOrEmpty(content[i]); i++)
            {
                string[] split = content[i].Split(',');

                // Skip to the next if not long enough
                if (split.Length < 6)
                {
                    continue;
                }

                // Parse station information
                Station sta = new Station();
                sta.StationMAC = split[0].Trim();
                sta.FirstTimeSeen = this.parseDateTime(split[1]);
                sta.LastTimeSeen = this.parseDateTime(split[2]);
                sta.Power = int.Parse(split[3].Trim());
                sta.NbPackets = ulong.Parse(split[4].Trim());
                sta.BSSID = split[5].Trim();

                // Get probed ESSID list
                if (split.Length > 6 && split[6] != "")
                {
                    List<string> list = new List<string>();
                    for (int j = 6; j < split.Length; j++)
                    {
                        // There's always a whitespace character before
                        list.Add(split[j].Substring(1));
                    }
                    sta.ProbedESSIDsList = list.ToArray();
                }
                else
                {
                    sta.ProbedESSIDs = string.Empty;
                }

                // Add station to the list
                this.addStation(sta);
            }

            // Link them together
            this.LinkAPClients();

            // Parsing was successful
            this.ParseSuccess = true;

            return this.ParseSuccess;
        }

        /// <summary>
        /// Returns the format of the file
        /// </summary>
        /// <param name="content">File content</param>
        /// <returns>CSV File Format</returns>
        /// <exception cref="ArgumentNullException">content is null</exception>
        /// <exception cref="ArgumentException">content is empty</exception>
        private CSVFileFormat getFormat(string[] content)
        {
            // Checks
            if (content == null)
            {
                throw new ArgumentNullException("Cannot determine format without any content");
            }
            if (content.Length == 1 && string.IsNullOrEmpty(content[0]))
            {
                throw new ArgumentException("Cannot determine format without any content");
            }

            // First line is empty and the second line contains the header
            if (content.Length > 2 && string.IsNullOrEmpty(content[0]))
            {
                // Version 1.x
                if (content[1] == "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key")
                {
                    return CSVFileFormat.v1X;
                }

                // Version 0.x
                if (content[1] == "BSSID, First time seen, Last time seen, Channel, Speed, Privacy, Power, # beacons, # data, LAN IP, ESSID")
                {
                    return CSVFileFormat.v0X;
                }
            }

            return CSVFileFormat.Unknown;
        }
    }
}
