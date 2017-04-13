----------------------------------------------------------------------------------
-- Company: University of New Mexico
-- Engineer: Professor Jim Plusquellic, Copyright Univ. of New Mexico
-- 
-- Create Date:
-- Design Name: 
-- Module Name:    DataTransferIn - Behavioral 
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
-- This module is responsible for getting data from the GPIO register into the data registers

library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC_STD.all;

library work;
use work.aes_pkg.all;

entity DataTransferIn is
   Port( 
      Clk : in std_logic;
      RESET: in std_logic;
      CP_restart: in std_logic;
      CP_data_ready: in std_logic; 
      SM_done_reading: out std_logic;
      Launch_GPIO_InVals: in std_logic_vector(15 downto 0);
      AES_key_in: out std_logic_vector(127 downto 0);
      AES_plaintext_in: out std_logic_vector(127 downto 0)
      );
end DataTransferIn;

architecture beh of DataTransferIn is
   type state_type is (idle, wait_data_ready);
   signal state_reg, state_next: state_type;

-- MAKE THIS large enough to handle AES_KEY/PLAIN _LB. ADD 1 extra bit since val_pos (AES_KEY/PLAIN _LB is 7) must count TO AES_KEY/PLAIN_IN_WIDTH_NB, 
-- which is 128 so we need 8-bits. 
   signal val_pos_reg, val_pos_next: unsigned(7 downto 0);
   signal load_select_reg, load_select_next: unsigned(1 downto 0);

   subtype val_pos_type is integer range 0 to 128;
   signal val_pos: val_pos_type;

   signal latch_vec_val: std_logic;

   signal AES_key_reg, AES_key_next: std_logic_vector(127 downto 0);
   signal AES_plaintext_reg, AES_plaintext_next: std_logic_vector(127 downto 0);

   begin

-- State and register logic
   process(Clk, RESET)
      begin
      if ( RESET = '1' ) then
         state_reg <= idle;
         val_pos_reg <= (others=>'0');
         load_select_reg <= (others=>'0');
         AES_key_reg <= (others=>'0');
         AES_plaintext_reg <= (others=>'0');
      elsif rising_edge(Clk) then
         state_reg <= state_next;
         val_pos_reg <= val_pos_next;
         load_select_reg <= load_select_next;
         AES_key_reg <= AES_key_next;
         AES_plaintext_reg <= AES_plaintext_next;
      end if; 
   end process;

-- ================================================================================================================
-- This state machine takes commands from the C program to control the loading of vectors 

   process (state_reg, CP_restart, CP_data_ready, val_pos_reg, load_select_reg)
      begin
      state_next <= state_reg;

      val_pos_next <= val_pos_reg;
      load_select_next <= load_select_reg;

      latch_vec_val <= '0';
      SM_done_reading <= '0';

      case state_reg is

-- =====================
-- The C program needs to load the AES plaintext and then the key.
         when idle =>

-- C program first asserts and then de-asserts 'CP_restart' to reset the pointers when loading vectors. 
            if ( CP_restart = '1' ) then
               val_pos_next <= (others=>'0');
               load_select_next <= (others=>'0');
            end if;

-- After the assertion/de-assertion of 'CP_restart', the C program asserts 'CP_data_ready' simultaneous with putting
-- a 16-bit chunk of data into the GPIO register. As soon as this state machine sees this 'CP_data_ready' flag asserted, 
-- it latches 16 bits by asserting 'latch_vec_val'. The state_machine keeps 'done_reading' low until it latches the data 
-- and then sets it to '1'. It then waits for the 'CP_data_ready' flag to go low, which is a handshake to this state 
-- machine (from the C program) that the C program acknowledges that it has seen the '1' on 'SM_done_reading'. So the C 
-- program should continue to assert 'CP_data_ready' with the current 16-bit chunk UNTIL it sees 'SM_done_reading' set 
-- to '1'. It should then de-assert 'CP_data_ready', loop, and then wait for 'SM_done_reading' to go back to '0' again. 
-- This completes the two-way handshake. The C program can then start the next cycle by re-asserting 'CP_data_ready' 
-- while simultaneously putting the next 16-bit chunk into the GPIO.
            if ( CP_data_ready = '1' ) then
               latch_vec_val <= '1';

-- PUF mode: Add 16 to the vec pos. 'val_pos_reg' tracks 16-bit chunks in the Launch_vecx and Mask
               val_pos_next <= val_pos_reg + 16;
               state_next <= wait_data_ready;
            end if;

-- =====================
-- C program must hold 'CP_data_ready' at 1 until it sees 'SM_done_reading' go to 1. This state machine then waits for the 
-- processor to write a '0' to 'CP_data_ready' before incrementing the RowTiming pointer.
         when wait_data_ready =>
            SM_done_reading <= '1';
            if ( CP_data_ready = '0' ) then

-- Add 16 to the plaintext/key. Fill in the plaintext first, and then fill in the key.
               if ( val_pos_reg = 128 ) then
                  load_select_next <= load_select_reg + 1;
                  val_pos_next <= (others=>'0');
               end if;

               state_next <= idle;
            end if;
      end case;
   end process;


-- =====================
-- Load that portion of the state inputs from the GPIO register indicated by the pointer registers set in the state machine above.
   val_pos <= to_integer(val_pos_reg);

   process (Launch_GPIO_InVals, latch_vec_val, load_select_reg, val_pos, CP_restart, AES_key_reg, AES_plaintext_reg)
      begin
      AES_key_next <= AES_key_reg;
      AES_plaintext_next <= AES_plaintext_reg;

-- Load data for encryption. Plaintext first and then key. 
      if ( latch_vec_val = '1' ) then
         if ( load_select_reg = 0 ) then
            AES_plaintext_next(val_pos + 15 downto val_pos) <= Launch_GPIO_InVals;
         else
            AES_key_next(val_pos + 15 downto val_pos) <= Launch_GPIO_InVals;
         end if;
      end if;

   end process;

   AES_key_in <= AES_key_reg;
   AES_plaintext_in <= AES_plaintext_reg;

end beh;

