// License: BSD/LGPL
// Copyright (C) 2011 Thomas d'Otreppe
using System;
using System.Collections.Generic;

namespace WirelessPanda
{
    public class AccessPoint : WirelessDevice, IEquatable<AccessPoint>
    {
        #region Properties
        /// <summary>
        /// Max Rate
        /// </summary>
        public double MaxRate
        {
            get
            {
                return (double)this.getDictValue("Max Rate");
            }
            set
            {
                this.setDictValue("Max Rate", value);
            }
        }

        /// <summary>
        /// Max Seen Rate
        /// </summary>
        public double MaxSeenRate
        {
            get
            {
                return (double)this.getDictValue("Max Seen Rate");
            }
            set
            {
                this.setDictValue("Max Seen Rate", value);
            }
        }

        /// <summary>
        /// Privacy
        /// </summary>
        public string Privacy
        {
            get
            {
                return (string)this.getDictValue("Privacy");
            }
            set
            {
                this.setDictValue("Privacy", value);
            }
        }

        /// <summary>
        /// Cipher
        /// </summary>
        public string Cipher
        {
            get
            {
                return (string)this.getDictValue("Cipher");
            }
            set
            {
                this.setDictValue("Cipher", value);
            }
        }

        /// <summary>
        /// Authentication
        /// </summary>
        public string Authentication
        {
            get
            {
                return (string)this.getDictValue("Authentication");
            }
            set
            {
                this.setDictValue("Authentication", value);
            }
        }

        /// <summary>
        /// # Data Frames
        /// </summary>
        public ulong DataFrames
        {
            get
            {
                return (ulong)this.getDictValue("Data");
            }
            set
            {
                this.setDictValue("Data", value);
            }
        }

        /// <summary>
        /// Beacons
        /// </summary>
        public long Beacons
        {
            get
            {
                return (long)this.getDictValue("Beacons");
            }
            set
            {
                this.setDictValue("Beacons", value);
            }
        }

        /// <summary>
        /// IP Address
        /// </summary>
        public string IP
        {
            get
            {
                return (string)this.getDictValue("IP");
            }
            set
            {
                this.setDictValue("IP", value);
            }
        }

        /// <summary>
        /// IP Type
        /// </summary>
        public int IPType
        {
            get
            {
                return (int)this.getDictValue("IP Type");
            }
            set
            {
                this.setDictValue("IP Type", value);
            }
        }

        /// <summary>
        /// ESSID
        /// </summary>
        public string ESSID
        {
            get
            {
                return (string)this.getDictValue("ESSID");
            }
            set
            {
                this.setDictValue("ESSID", value);
            }
        }

        /// <summary>
        /// ESSID Length
        /// </summary>
        public byte ESSIDLength
        {
            get
            {
                return (byte)this.getDictValue("ESSID Length");
            }
            set
            {
                this.setDictValue("ESSID Length", value);
            }
        }

        /// <summary>
        /// Key
        /// </summary>
        public string Key
        {
            get
            {
                return (string)this.getDictValue("Key");
            }
            set
            {
                this.setDictValue("Key", value);
            }
        }

        /// <summary>
        /// Network Type
        /// </summary>
        public string NetworkType
        {
            get
            {
                return (string)this.getDictValue("Network Type");
            }
            set
            {
                this.setDictValue("Network Type", value);
            }
        }

        /// <summary>
        /// Info
        /// </summary>
        public string Info
        {
            get
            {
                return (string)this.getDictValue("Info");
            }
            set
            {
                this.setDictValue("Info", value);
            }
        }

        /// <summary>
        /// Encoding
        /// </summary>
        public string Encoding
        {
            get
            {
                return (string)this.getDictValue("Encoding");
            }
            set
            {
                this.setDictValue("Encoding", value);
            }
        }

        /// <summary>
        /// Cloaked ?
        /// </summary>
        public bool Cloaked
        {
            get
            {
                return (bool)this.getDictValue("Cloaked");
            }
            set
            {
                this.setDictValue("Cloaked", value);
            }
        }

        /// <summary>
        /// Encryption
        /// </summary>
        public string Encryption
        {
            get
            {
                return (string)this.getDictValue("Encryption");
            }
            set
            {
                this.setDictValue("Encryption", value);
            }
        }

        /// <summary>
        /// Is the traffic decrypted?
        /// </summary>
        public bool Decrypted
        {
            get
            {
                return (bool)this.getDictValue("Decrypted");
            }
            set
            {
                this.setDictValue("Decrypted", value);
            }
        }

        /// <summary>
        /// # Beacon Frames
        /// </summary>
        public ulong Beacon
        {
            get
            {
                return (ulong)this.getDictValue("Beacon");
            }
            set
            {
                this.setDictValue("Beacon", value);
            }
        }

        /// <summary>
        /// # LLC Frames
        /// </summary>
        public ulong LLC
        {
            get
            {
                return (ulong)this.getDictValue("LLC");
            }
            set
            {
                this.setDictValue("LLC", value);
            }
        }

        /// <summary>
        /// # Crypt Frames
        /// </summary>
        public ulong Crypt
        {
            get
            {
                return (ulong)this.getDictValue("Crypt");
            }
            set
            {
                this.setDictValue("Crypt", value);
            }
        }

        /// <summary>
        /// # Weak Frames
        /// </summary>
        public ulong Weak
        {
            get
            {
                return (ulong)this.getDictValue("Weak");
            }
            set
            {
                this.setDictValue("Weak", value);
            }
        }

        /// <summary>
        /// Total Nb of Frames
        /// </summary>
        public ulong Total
        {
            get
            {
                return (ulong)this.getDictValue("Total");
            }
            set
            {
                this.setDictValue("Total", value);
            }
        }

        /// <summary>
        /// Carrier
        /// </summary>
        public string Carrier
        {
            get
            {
                return (string)this.getDictValue("Carrier");
            }
            set
            {
                this.setDictValue("Carrier", value);
            }
        }

        /// <summary>
        /// Best Quality
        /// </summary>
        public int BestQuality
        {
            get
            {
                return (int)this.getDictValue("BestQuality");
            }
            set
            {
                this.setDictValue("BestQuality", value);
            }
        }

        /// <summary>
        /// Best Signal
        /// </summary>
        public int BestSignal
        {
            get
            {
                return (int)this.getDictValue("Best Signal");
            }
            set
            {
                this.setDictValue("Best Signal", value);
            }
        }

        /// <summary>
        /// Best Noise
        /// </summary>
        public int BestNoise
        {
            get
            {
                return (int)this.getDictValue("Best Noise");
            }
            set
            {
                this.setDictValue("Best Noise", value);
            }
        }

        /// <summary>
        /// Min Location
        /// </summary>
        public Coordinates MinLocation
        {
            get
            {
                return (Coordinates)this.getDictValue("Min Location");
            }
            set
            {
                this.setDictValue("Min Location", value);
            }
        }

        /// <summary>
        /// Best Location
        /// </summary>
        public Coordinates BestLocation
        {
            get
            {
                return (Coordinates)this.getDictValue("Best Location");
            }
            set
            {
                this.setDictValue("Best Location", value);
            }
        }

        /// <summary>
        /// Max Location
        /// </summary>
        public Coordinates MaxLocation
        {
            get
            {
                return (Coordinates)this.getDictValue("Max Location");
            }
            set
            {
                this.setDictValue("Max Location", value);
            }
        }

        /// <summary>
        /// Data Size
        /// </summary>
        public ulong DataSize
        {
            get
            {
                return (ulong)this.getDictValue("Data Size");
            }
            set
            {
                this.setDictValue("Data Size", value);
            }
        }
        #endregion

        /// <summary>
        /// Internal list of client
        /// </summary>
        private List<Station> _clientList = new List<Station>();

        /// <summary>
        /// Add a client to our list
        /// </summary>
        /// <param name="sta"></param>
        public void addClient(Station sta)
        {
            this._clientList.Add(sta);
            sta.AP = this;
        }

        /// <summary>
        /// Returns the client list
        /// </summary>
        public List<Station> ClientList
        {
            get
            {
                return this._clientList;
            }
        }

        /// <summary>
        /// Implements IEquatable
        /// </summary>
        /// <param name="other">Other AccessPoint to compare to</param>
        /// <returns>true if equals, false if not</returns>
        public bool Equals(AccessPoint other)
        {
            try
            {
                if (this.BSSID == other.BSSID)
                {
                    return true;
                }
            }
            catch { }

            return false;
        }
    }
}
