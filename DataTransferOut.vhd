----------------------------------------------------------------------------------
-- Company: University of New Mexico
-- Engineer: Professor Jim Plusquellic, Copyright Univ. of New Mexico
-- 
-- Create Date:
-- Design Name: 
-- Module Name:    DataTransferOut - Behavioral 
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
-- This module is responsible transfering data back to the C program

library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC_STD.all;

library work;
use work.aes_pkg.all;

entity DataTransferOut is
   Port( 
      Clk : in std_logic;
      RESET: in std_logic;
      CP_restart: in std_logic;
      CP_done_reading: in std_logic;
      SM_data_ready: out std_logic;
      AES_ciphertext_out: in std_logic_vector(127 downto 0);
      AES_ciphertext_out_chunk: out std_logic_vector(15 downto 0)
      );
end DataTransferOut;


architecture beh of DataTransferOut is
   type state_type is (idle, wait_CP_ack);
   signal state_reg, state_next: state_type;

-- Used to index timing values and mask (and possibly ciphertext in multiples of 16).
   signal output_index_reg, output_index_next: unsigned(3 downto 0);

   subtype ciphertext_pos_type is integer range 0 to 127;
   signal ciphertext_pos: ciphertext_pos_type;

   begin

-- State and register logic
   process(Clk, RESET)
      begin
      if (RESET = '1') then
         state_reg <= idle;
         output_index_reg <= (others=>'0');
      elsif rising_edge(Clk) then
         state_reg <= state_next;
         output_index_reg <= output_index_next;
      end if; 
   end process;

-- ================================================================================================================
-- This state machine monitors a C program flag to determine it is done reading the data.

   process (state_reg, CP_restart, CP_done_reading, output_index_reg)
      begin
      state_next <= state_reg;

      output_index_next <= output_index_reg;

      SM_data_ready <= '1';

      case state_reg is

-- =====================
         when idle =>

-- Controller issues a restart to reset the pointers. This puts first data chunk on the GPIO output register. The data chunks
-- are sent back from lowest to highest.
            if ( CP_restart = '1' ) then
               output_index_next <= (others=>'0');
            end if;

-- Wait for the controller to write a '1' indicating it has read the data. Immediately deassert SM_data_ready flag to 
-- controller to force the C program to wait until the counters are updated. Note that the address update does NOT
-- occur until the C program de-asserts 'CP_done_reading'
            if ( CP_done_reading = '1' ) then
               SM_data_ready <= '0';
               state_next <= wait_CP_ack;
            end if;

-- =====================
-- Processor should hold 'CP_done_reading' at 1 until it sees 'SM_data_ready' go to 0. At that point, the processor sets 
-- 'CP_done_reading' to 0 as an acknowledgement. The data pointers are then updated.
         when wait_CP_ack =>
            SM_data_ready <= '0';
            if ( CP_done_reading = '0' ) then

-- A simple counter from 0 to n-1 used as an index below. 
               output_index_next <= output_index_reg + 1;
               state_next <= idle;
            end if;
      end case;
   end process;

-- Restrict the range of 'output_index_reg' to 0 to 7 here.
   ciphertext_pos <= to_integer(output_index_reg)*16 when output_index_reg < 8 else 0;
   AES_ciphertext_out_chunk <= AES_ciphertext_out(ciphertext_pos + 15 downto ciphertext_pos);

end beh;

