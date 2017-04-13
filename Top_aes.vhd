----------------------------------------------------------------------------------
-- Company: University of New Mexico
-- Engineer: Professor Jim Plusquellic, Copyright Univ. of New Mexico
-- 
-- Create Date:
-- Design Name: 
-- Module Name:    Top - Behavioral 
-- Project Name: 
-- Target Devices: 
-- Tool versions: 
-- Description: 
--
-- Dependencies: 
--
-- Revision: 
-- Revision 0.01 - File Created
-- Additional Comments: 
--
----------------------------------------------------------------------------------

-- ===================================================================================================
-- ===================================================================================================
library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC_STD.all;

library work;
use work.aes_pkg.all;

entity Top is
   port (
      Clk: in std_logic;
      GPIO_Ins: in std_logic_vector(31 downto 0);
      GPIO_Outs: out std_logic_vector(31 downto 0);
      Scope_trigger: out std_logic;
      RESET_N_EXT: in std_logic
      );
end Top;

architecture beh of Top is

-- GPIO INPUT BIT ASSIGNMENTS
   constant IN_CP_RESET: integer := 31;

   constant SCOPE_TRIGGER: integer := 23;
   constant IN_CP_START_ENCRYPTION: integer := 22;
   constant IN_CP_DTI_DATA_READY: integer := 20;
   constant IN_CP_DTI_RESTART: integer := 19;
   constant IN_CP_DTO_DONE_READING: integer := 17;
   constant IN_CP_DTO_RESTART: integer := 16;

-- GPIO OUTPUT BIT ASSIGNMENTS
   constant OUT_SM_READY: integer := 31;
   constant OUT_SM_DTO_DATA_READY: integer := 30;
   constant OUT_SM_DTI_DONE_READING: integer := 29;

-- Data out is set to 16.
   constant OUT_DATA_LEN_NB: integer := 16;

   signal DataTransIn_CP_DTI_data_ready: std_logic; 
   signal DataTransIn_SM_DTI_done_reading: std_logic; 

   signal GLB_DTI_restart: std_logic;
   signal GLB_DTO_restart: std_logic;
   signal GLB_DTO_done_reading: std_logic;
   signal GLB_DTO_data_ready: std_logic;

-- Functional unit signals
   signal Top_AES_ready: std_logic;
   signal AES_key_in: std_logic_vector(127 downto 0);
   signal AES_plaintext_in: std_logic_vector(127 downto 0);
   signal AES_ciphertext_out: std_logic_vector(127 downto 0);
   signal AES_ciphertext_out_chunk: std_logic_vector(15 downto 0);

   signal GLB_start_encryption: std_logic;

   signal RESET: std_logic;


-- =======================================================================================================
   begin

-- Allow C program to start encryption algorithm.
   GLB_start_encryption <= GPIO_Ins(IN_CP_START_ENCRYPTION);

-- -----------------------
-- DataTransferIn control
   GLB_DTI_restart <= GPIO_Ins(IN_CP_DTI_RESTART);

-- These are used to allow data from the C program to be transferred into DataTransferIn. 
   DataTransIn_CP_DTI_data_ready <= GPIO_Ins(IN_CP_DTI_DATA_READY); 
   GPIO_Outs(OUT_SM_DTI_DONE_READING) <= DataTransIn_SM_DTI_done_reading; 

-- -----------------------
-- DataTransferOut control:
-- Resets registers pointers in prep for data transfer. C program controls DataTransferOut when 'MST_in_control' is '0', otherwise,
-- CollectPNs controls it so it can get the timing values after a vector pair is applied and path timing values become available.
   GLB_DTO_restart <= GPIO_Ins(IN_CP_DTO_RESTART);

-- DataTransfer out control -- tells DTO state machine to advance to next stored timing value. 
   GLB_DTO_done_reading <= GPIO_Ins(IN_CP_DTO_DONE_READING);

-- Software (C code) plus hardware global reset
   RESET <= GPIO_Ins(IN_CP_RESET) or not RESET_N_EXT;

   Scope_trigger <= GPIO_Ins(SCOPE_TRIGGER);

-- =====================
-- DataTransfer Modules

-- Transfer key and plaintext into the VHDL code from the PS side. 'CP_restart' resets the register bank pointers to 0 which
-- is done prior do sending the first 16-bit chunk. 'CP_data_ready' is '1' when the C program has a 16-bit chunk available 
-- for transfer. 
   DataTranInMod: entity work.DataTransferIn(beh)
      port map (Clk=>Clk, RESET=>RESET, CP_restart=>GLB_DTI_restart, CP_data_ready=>DataTransIn_CP_DTI_data_ready, 
         SM_done_reading=>DataTransIn_SM_DTI_done_reading, Launch_GPIO_InVals=>GPIO_Ins(15 downto 0), AES_key_in=>AES_key_in, 
         AES_plaintext_in=>AES_plaintext_in);

-- Transfer the data back to the PS side. Asserting 'CP_restart' resets the data pointers back to 0 and is carried out prior to 
-- unloading ciphertext. C program/state machine then writes a '1' to 'CP_done_reading', and then a '0', and then waits for 
-- 'SM_data_ready' to be '1' before reading next chunk. Repeat last statement until all chunks are read.
   DataTranOutMod: entity work.DataTransferOut
      port map (Clk=>Clk, RESET=>RESET, CP_restart=>GLB_DTO_restart, CP_done_reading=>GLB_DTO_done_reading, 
         SM_data_ready=>GLB_DTO_data_ready, AES_ciphertext_out=>AES_ciphertext_out, AES_ciphertext_out_chunk=>AES_ciphertext_out_chunk);

-- =====================
-- DATA OUT: Control and status signals
   GPIO_Outs(OUT_SM_READY) <= Top_AES_ready;
   GPIO_Outs(OUT_SM_DTO_DATA_READY) <= GLB_DTO_data_ready;

   GPIO_Outs(OUT_DATA_LEN_NB-1 downto 0) <= AES_ciphertext_out_chunk;

-- =====================
-- The functional unit and PUF entropy source
   FUWMod: entity work.aes_top(rtl)
      port map(Clk=>Clk, RESET=>RESET, start=>GLB_start_encryption, ready=>Top_AES_ready, key_in=>AES_key_in, 
         plaintext_in=>AES_plaintext_in, ciphertext_out=>AES_ciphertext_out);
               
          
end beh;


