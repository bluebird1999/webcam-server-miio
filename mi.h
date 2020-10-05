#ifndef SERVER_MIIO_MI_H_
#define SERVER_MIIO_MI_H_

/*
 * header
 */

/*
 * define
 */
#define IID_1_DeviceInformation                                               1
#define IID_1_1_Manufacturer                                                  1
#define IID_1_2_Model                                                         2
#define IID_1_3_SerialNumber                                                  3
#define IID_1_4_FirmwareRevision                                              4

#define IID_2_CameraControl                                                   2
#define IID_2_1_On                                                            1
#define IID_2_2_ImageRollover                                                 2
#define IID_2_3_NightShot                                                     3
#define IID_2_4_TimeWatermark                                                 4
#define IID_2_5_WdrMode                                                       5
#define IID_2_6_GlimmerFullColor                                              6
#define IID_2_7_RecordingMode                                                 7
#define IID_2_8_MotionTracking                                                8

#define IID_3_IndicatorLight                                                  3
#define IID_3_1_On                                                            1

#define IID_4_MemoryCardManagement                                            4
#define IID_4_1_Status                                                        1
#define IID_4_2_StorageTotalSpace                                             2
#define IID_4_3_StorageFreeSpace                                              3
#define IID_4_4_StorageUsedSpace                                              4
#define IID_4_1_Format                                                        1
#define IID_4_2_PopUp                                                         2

#define IID_5_MotionDetection                                                 5
#define IID_5_1_MotionDetection                                               1
#define IID_5_2_AlarmInterval                                                 2
#define IID_5_3_DetectionSensitivity                                          3
#define IID_5_4_MotionDetectionStartTime                                      4
#define IID_5_5_MotionDetectionEndTime                                        5

#define IID_6_MoreSet                                                         6
#define IID_6_1_Ipaddr                                                        1
#define IID_6_2_MacAddr                                                       2
#define IID_6_3_WifiName                                                      3
#define IID_6_4_WifiRssi                                                      4
#define IID_6_5_CurrentMode                                                   5
#define IID_6_6_TimeZone                                                      6
#define IID_6_7_StorageSwitch                                                 7
#define IID_6_8_CloudUploadEnable                                             8
#define IID_6_9_MotionAlarmPush                                               9
#define IID_6_10_DistortionSwitch                                             10
#define IID_6_1_Reboot                                                        1
/*
 * structure
 */

/*
 * function
 */


#endif /* SERVER_MIIO_MI_H_ */
