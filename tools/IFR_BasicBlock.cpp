/*
 * @Date: 2022-03-29 17:50:40
 * @LastEditors: zx Zhou
 * @LastEditTime: 2022-03-29 18:18:21
 * @FilePath: /libdft64/tools/IFR_BasicBlock.cpp
   @Author: https://github.com/JaonLin/PinCFG/
*/


#include "IFR_BasicBlock.h"

IFR_BasicBlock::IFR_BasicBlock(){
  
  insns = vector<INS>();

}

IFR_BasicBlock::IFR_BasicBlock(const IFR_BasicBlock& other){

  insns = vector<INS>();
  insns.assign( other.insns.begin(), other.insns.end() ); 
  target = other.target;
  fallthrough = other.fallthrough;
  isReturn = other.isReturn;

}

IFR_BasicBlock IFR_BasicBlock::operator=(const IFR_BasicBlock& other){

  insns.assign( other.insns.begin(), other.insns.end() ); 
  target = other.target;
  fallthrough = other.fallthrough;
  isReturn = other.isReturn;
  return *this;
}
  
void IFR_BasicBlock::add(INS ins){
  insns.push_back(ins); 
}


ADDRINT IFR_BasicBlock::getEntryAddr(){
  return INS_Address(*(insns.begin()));
}

ADDRINT IFR_BasicBlock::getLastAddr(){
  vector<INS>::iterator tmp;
  tmp = insns.end();
  --tmp;
  return INS_Address(*tmp);
}

void IFR_BasicBlock::setTarget(ADDRINT targ){
  target = targ;
}

ADDRINT IFR_BasicBlock::getTarget(){
  return target;
}


void IFR_BasicBlock::setFallthrough(ADDRINT ft){
  fallthrough = ft;
}

ADDRINT IFR_BasicBlock::getFallthrough(){
  return fallthrough;
}

void IFR_BasicBlock::setIsReturn(bool is){
  isReturn = is;
}

void IFR_BasicBlock::clear(){

  fallthrough = target = 0;
  isReturn = false;
  insns.clear();

}


