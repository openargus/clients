#ifndef __RAHISTO_H
# define __RAHISTO_H

struct RaHistoConfigStruct {
   int RaHistoMetricLog;
   int RaHistoRangeState;
   int RaHistoBins;
   int ArgusPassNum;
   double RaHistoLogInterval;
   double RaHistoBinSize;
   double RaHistoStart;
   double RaHistoStartLog;
   double RaHistoEnd;
   double RaHistoEndLog;
};

/* struct ArgusRecordStruct **RaHistoRecords; */

#endif
