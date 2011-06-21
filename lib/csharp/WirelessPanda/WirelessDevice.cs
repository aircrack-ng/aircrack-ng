// License: BSD/LGPL
// Copyright (C) 2011 Thomas d'Otreppe
using System;
using System.Collections;

namespace WirelessPanda
{
    public abstract class WirelessDevice
    {
        #region Dictionary stuff
        /// <summary>
        /// Keep track of the last position for the column
        /// </summary>
        private int _lastPosition = 0;
        
        /// <summary>
        /// Dictionary containing all values
        /// </summary>
        protected Hashtable _fieldsDictionary = new Hashtable();

        /// <summary>
        /// Order of the columns
        /// </summary>
        protected Hashtable _fieldsOrder = new Hashtable();

        /// <summary>
        /// Sets a value in the dictionary
        /// </summary>
        /// <param name="key">Key</param>
        /// <param name="value">Value</param>
        protected void setDictValue(string key, object value)
        {
            if (this._fieldsDictionary.ContainsKey(key))
            {
                this._fieldsDictionary.Remove(key);
            }
            else
            {
                // Save the position for the column (useful when creating the dataset)
                this._fieldsOrder.Add(this._lastPosition++, key);
            }

            this._fieldsDictionary.Add(key, value);
        }

        /// <summary>
        /// Return a value in the dictionary
        /// </summary>
        /// <param name="key">Key</param>
        /// <returns>Object value</returns>
        /// <exception cref="MissingFieldException"></exception>
        protected object getDictValue(string key)
        {
            if (this._fieldsDictionary.ContainsKey(key))
            {
                return this._fieldsDictionary[key];
            }

            throw new MissingFieldException("Value for <" + key + "> is not set or does not exist");
        }

        /// <summary>
        /// Returns a copy of the dictionary
        /// </summary>
        internal Hashtable FieldsDictionary
        {
            get
            {
                return this._fieldsDictionary as Hashtable;
            }
        }

        /// <summary>
        /// Returns a copy of the column order
        /// </summary>
        internal Hashtable FieldsOrder
        {
            get
            {
                return this._fieldsOrder as Hashtable;
            }
        }
        #endregion

        #region Properties
        public string BSSID
        {
            get
            {
                return (string)this.getDictValue("BSSID");
            }
            set
            {
                this.setDictValue("BSSID", value);

                if (value != null)
                {
                    // Special case, not associated
                    if (value.Trim() == "(not associated)")
                    {
                        this.setDictValue("BSSID", string.Empty);
                    }
                    else
                    {
                        this.setDictValue("BSSID", value.Trim());
                    }
                }
            }
        }

        public DateTime FirstTimeSeen
        {
            get
            {
                return (DateTime)this.getDictValue("First Time Seen");
            }
            set
            {
                this.setDictValue("First Time Seen", value);
            }
        }

        public DateTime LastTimeSeen
        {
            get
            {
                return (DateTime)this.getDictValue("Last Time Seen");
            }
            set
            {
                this.setDictValue("Last Time Seen", value);
            }
        }

        public int Channel
        {
            get
            {
                return (int)this.getDictValue("Channel");
            }
            set
            {
                this.setDictValue("Channel", value);
            }
        }

        public ulong TotalFrames
        {
            get
            {
                return (ulong)this.getDictValue("Total Frames");
            }
            set
            {
                this.setDictValue("Total Frames", value);
            }
        }

        public Coordinates Location
        {
            get
            {
                return (Coordinates)this.getDictValue("Location");
            }
            set
            {
                this.setDictValue("Location", value);
            }
        }

        public int Power
        {
            get
            {
                return (int)this.getDictValue("Power");
            }
            set
            {
                this.setDictValue("Power", value);
            }
        }
        #endregion
    }
}
