// License: BSD/LGPL
// Copyright (C) 2011 Thomas d'Otreppe
using System;
using System.Collections.Generic;
using System.Text;

namespace WirelessPanda
{
    public class Station : WirelessDevice, IEquatable<Station>
    {
        
        private AccessPoint _ap = null;

        /// <summary>
        /// Access point
        /// </summary>
        public AccessPoint AP
        {
            get
            {
                return this._ap;
            }
            // Only allow to do it inside the lib
            internal set
            {
                this._ap = value;
            }
        }

        /// <summary>
        /// Station MAC
        /// </summary>
        public string StationMAC
        {
            get
            {
                return (string)this.getDictValue("Station MAC");
            }
            set
            {
                if (value != null)
                {
                    this.setDictValue("Station MAC", value.Trim());
                }
                else
                {
                    this.setDictValue("Station MAC", value);
                }
            }
        }

        /// <summary>
        /// # Packets
        /// </summary>
        public ulong NbPackets
        {
            get
            {
                return (ulong)this.getDictValue("# Packets");
            }
            set
            {
                this.setDictValue("# Packets", value);
            }
        }

        /// <summary>
        /// Probed ESSIDs (comma separated)
        /// </summary>
        public string ProbedESSIDs
        {
            get
            {
                return (string)this.getDictValue("Probed ESSIDs");
            }
            set
            {
                this.setDictValue("Probed ESSIDs", value);

                // Update probe ESSID list
                this._probedESSIDsList.Clear();
                if (string.IsNullOrEmpty(value))
                {
                    foreach (string s in value.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (string.IsNullOrEmpty(s.Trim()))
                        {
                            continue;
                        }

                        // Add ESSID
                        this._probedESSIDsList.Add(s);
                    }
                }
            }
        }


        private List<string> _probedESSIDsList = new List<string>();
        /// <summary>
        /// Probed ESSIDs List 
        /// </summary>
        public string[] ProbedESSIDsList
        {
            get
            {
                return _probedESSIDsList.ToArray().Clone() as string[];
            }
            set
            {
                this._probedESSIDsList.Clear();
                this.setDictValue("Probed ESSIDs", string.Empty);
                if (value != null && value.Length > 0)
                {
                    this._probedESSIDsList.AddRange(value);

                    // Generate the string list of SSID
                    StringBuilder sb = new StringBuilder(string.Empty);
                    foreach (string s in value)
                    {
                        sb.AppendFormat("{0}, ", s);
                    }

                    string res = sb.ToString();
                    if (res.Length > 0)
                    {
                        res = res.Substring(0, res.Length - 2);
                    }

                    // And put it in the Probed ESSIDs dictionary item
                    this.setDictValue("Probed ESSIDs", res);
                }
            }
        }

        /// <summary>
        /// Implements IEquatable
        /// </summary>
        /// <param name="other">Other Station to compare to</param>
        /// <returns>true if equals, false if not</returns>
        public bool Equals(Station other)
        {
            try
            {
                if (this.StationMAC == other.StationMAC)
                {
                    return true;
                }
            }
            catch { }

            return false;
        }
    }
}
