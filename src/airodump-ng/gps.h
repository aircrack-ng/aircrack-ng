#ifndef __GPS_H__
#define __GPS_H__

typedef enum
{
	gps_latitude,
	gps_longitude,
	gps_speed,
	gps_heading,
	gps_altitude,
	gps_latitude_error,
	gps_longitude_error,
	gps_altitude_error,
	gps_location_COUNT
} gps_location_t;

#endif /* __GPS_H__ */
