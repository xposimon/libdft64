/*
 * @Date: 2022-03-29 17:49:16
 * @LastEditors: zx Zhou
 * @LastEditTime: 2022-03-29 18:24:35
 * @FilePath: /libdft64/tools/fuzz_cfg.cpp
 * @Author: https://github.com/JaonLin/PinCFG/
 */

#include <fstream>
#include <iostream>
#include <hash_map>
#include <set>

using namespace std;

#include "IFR_BasicBlock.h"

#define OUTPUT_PATH "./scripts/info/fuzz_cfg.info"

ofstream out;


INT32 usage()
{
    cerr << "Fuzz CFG";
    cerr << endl;
    return -1;
}

void findBlocks(RTN rtn, 
                vector<IFR_BasicBlock> &bblist, 
                hash_map<ADDRINT, IFR_BasicBlock> &blocks){

  /*Takes a PIN RTN object and returns a set containing the 
   *addresses of the instructions that are entry points to basic blocks
   *"Engineering a Compiler pg 439, Figure 9.1 'Finding Leaders'"
   */
  set<ADDRINT> leaders = set<ADDRINT>();
  bool first = true;
  for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)){

    if( first ){
      first = false;
      leaders.insert( INS_Address(ins) );
    }

    if( INS_IsBranch(ins) ){

      assert( !INS_IsRet(ins) );
      if( !INS_IsIndirectControlFlow(ins) ){
      
        leaders.insert(INS_DirectControlFlowTargetAddress(ins));
        leaders.insert(INS_NextAddress(ins));

      }/*else{

        Calls and Indirect Branches may go anywhere, so we conservatively assume they jump to the moon

      }*/

    }

  }


  IFR_BasicBlock bb = IFR_BasicBlock();   
  for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)){

    bb.add(ins);

    INS next = INS_Next(ins);
    if(   (INS_Valid(next) &&  leaders.find(INS_Address(next)) != leaders.end()) || !INS_Valid(next) ){

      /*Next is a block leader or end of routine -- End the block here*/

      if( INS_IsBranch(ins) ){

        /*Block ends with a branch insn*/

        assert( !INS_IsRet(ins) );
        if( !INS_IsIndirectControlFlow(ins) ){

          /*End of block with Direct Branch insns*/        
          bb.setTarget(INS_DirectControlFlowTargetAddress(ins));
          if( INS_Category(ins) != XED_CATEGORY_UNCOND_BR ){
            bb.setFallthrough(INS_NextAddress(ins));
          }else{
            bb.setFallthrough(0);
          }

        }

      }else{

        /*Block ends with a non-branch insn*/
        bb.setTarget(0);
        bb.setFallthrough(INS_NextAddress(ins));

      }

      blocks.insert( std::pair<ADDRINT,IFR_BasicBlock>(bb.getEntryAddr(), IFR_BasicBlock(bb)) ); 
      bblist.push_back(IFR_BasicBlock(bb));
      bb.clear();

    }

  }

  return;
   
}

void computePredecessors(RTN rtn, 
                         vector<IFR_BasicBlock> &bblist, 
                         hash_map<ADDRINT, set<ADDRINT> > &pred){

  
  pred[ bblist.begin()->getEntryAddr() ] = set<ADDRINT>(); 
  for( vector<IFR_BasicBlock>::iterator i = bblist.begin(); i != bblist.end(); i++){

    if( pred.find( i->getTarget() ) == pred.end() ){
      pred[ i->getTarget() ] = set<ADDRINT>();
    }    
    
    if( pred.find( i->getFallthrough() ) == pred.end() ){
      pred[ i->getFallthrough() ] = set<ADDRINT>();
    }    

    pred[ i->getTarget() ].insert( i->getEntryAddr() );
    pred[ i->getFallthrough() ].insert( i->getEntryAddr() );

  }
  return;

}

VOID instrumentRoutine(RTN rtn, VOID *v){
 

  RTN_Open(rtn);
  if( !RTN_Valid(rtn) || !IMG_IsMainExecutable( IMG_FindByAddress( RTN_Address(rtn) ) )){
    RTN_Close(rtn);
    return;
  }
  out.open(OUTPUT_PATH, ios::app);

  out<<"[RT]"<<RTN_Name(rtn).c_str()<<endl;

  vector<IFR_BasicBlock> bblist = vector<IFR_BasicBlock>(); 
  hash_map<ADDRINT, IFR_BasicBlock> blocks = hash_map<ADDRINT, IFR_BasicBlock>();
  findBlocks(rtn,bblist,blocks); 
  
  hash_map<ADDRINT, set<ADDRINT> > pred = hash_map<ADDRINT, set<ADDRINT> >();
  computePredecessors(rtn,bblist,pred);

 
    for( vector<IFR_BasicBlock>::iterator i = bblist.begin(); i != bblist.end(); i++){
        out<<"[BB]"<<std::hex<<i->getEntryAddr()<<":"<<i->getLastAddr()<<endl;
        for( set<ADDRINT>::iterator pi = pred[ i->getEntryAddr() ].begin();
            pi != pred[ i->getEntryAddr() ].end(); pi++ ){
            out<<"[Ex]"<<std::hex<<*pi<<"=>"<<i->getEntryAddr()<<endl;
        }
    }

  out.close();
  RTN_Close(rtn);

}



int main(int argc, char *argv[])
{

  PIN_InitSymbols();
  if( PIN_Init(argc,argv) ) {
    return usage();
  }

  RTN_AddInstrumentFunction(instrumentRoutine,0);

  PIN_StartProgram();
  
  return 0;
}
