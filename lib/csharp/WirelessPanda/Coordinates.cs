// License: BSD/LGPL
// Copyright (C) 2011-2018 Thomas d'Otreppe
using System;
using System.Collections;
using System.Text;

namespace WirelessPanda
{
    public class Coordinates
    {
        #region Dictionary stuff
        private Hashtable _dictionary = new Hashtable();

        private void setDictValue(string elem, double value)
        {
            if (this._dictionary.ContainsKey(elem))
            {
                this._dictionary.Remove(elem);
            }
            this._dictionary.Add(elem, value);
        }

        private double getDictValue(string elem)
        {
            if (this._dictionary.ContainsKey(elem))
            {
                return (double)this._dictionary[elem];
            }

            throw new MissingFieldException("Value <" + elem + "> is not set or does not exist");
        }
        #endregion

        #region Properties
        /// <summary>
        /// Latitude
        /// </summary>
        public double Latitude
        {
            get
            {
                return this.getDictValue("Latitude");
            }
            set
            {
                this.setDictValue("Latitude", value);
            }
        }

        /// <summary>
        /// Longitude
        /// </summary>
        public double Longitude
        {
            get
            {
                return this.getDictValue("Longitude");
            }
            set
            {
                this.setDictValue("Longitude", value);
            }
        }

        /// <summary>
        /// Altitude (in meters)
        /// </summary>
        public double Altitude
        {
            get
            {
                return this.getDictValue("Altitude");
            }
            set
            {
                this.setDictValue("Altitude", value);
            }
        }

        /// <summary>
        /// Speed (UOM: probably knot but unsure)
        /// </summary>
        public double Speed
        {
            get
            {
                return this.getDictValue("Speed");
            }
            set
            {
                this.setDictValue("Speed", value);
            }
        }
        #endregion

        public Coordinates(string latitude = null, string longitude = null, string altitude = null, string speed = null)
        {
            if (!string.IsNullOrEmpty(latitude))
            {
                this.Latitude = double.Parse(latitude);
            }

            if (!string.IsNullOrEmpty(longitude))
            {
                this.Longitude = double.Parse(longitude);
            }

            if (!string.IsNullOrEmpty(altitude))
            {
                this.Altitude = double.Parse(altitude);
            }

            if (!string.IsNullOrEmpty(speed))
            {
                this.Speed = double.Parse(speed);
            }
        }

        public Coordinates(double latitude, double longitude)
        {
            this.Latitude = latitude;
        }

        public Coordinates(double latitude, double longitude, double altitude) : this(latitude, longitude)
        {
            this.Altitude = latitude;
        }

        public Coordinates(double latitude, double longitude, double altitude, double speed) : this(latitude, longitude, altitude)
        {
            this.Speed = speed;
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            try
            {
                sb.Append(this.Latitude);
                sb.Append(", ");
                sb.Append(this.Longitude);


                if (this._dictionary.ContainsKey("Altitude"))
                {
                    sb.Append(" - Altitude: ");
                    sb.Append(this.Altitude);
                }

                if (this._dictionary.ContainsKey("Speed"))
                {
                    sb.Append(" - Speed: ");
                    sb.Append(this.Speed);
                }
            
            }
            catch
            {
                if (sb.Length > 0)
                {
                    sb.Remove(0, sb.Length);
                }
            }

            return sb.ToString();
        }
    }
}
