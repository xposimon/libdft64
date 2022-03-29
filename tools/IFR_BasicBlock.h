/*
 * @Date: 2022-03-29 17:50:40
 * @LastEditors: zx Zhou
 * @LastEditTime: 2022-03-29 18:18:03
 * @FilePath: /libdft64/tools/IFR_BasicBlock.h
   @Author: https://github.com/JaonLin/PinCFG/
*/

#include <vector>
#include <pin.H>
using std::vector;
class IFR_BasicBlock{

  ADDRINT target;
  ADDRINT fallthrough;
  bool isReturn;

public:

  IFR_BasicBlock();

  IFR_BasicBlock(const IFR_BasicBlock&); //copy constructor
  IFR_BasicBlock operator=(const IFR_BasicBlock&); //to handle explicit assignment

  void add(INS ins);
  
  ADDRINT getEntryAddr();
  ADDRINT getLastAddr();
  void setTarget(ADDRINT targ);
  void setFallthrough(ADDRINT ft);
  ADDRINT getTarget();
  ADDRINT getFallthrough();
 
  void setIsReturn(bool is);

  void clear();
  

  std::vector<INS> insns;

};
