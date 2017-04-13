----------------------------------------------------------------------
----                                                              ----
---- Pipelined Aes IP Core                                        ----
----                                                              ----
---- This file is part of the Pipelined AES project               ----
---- http://www.opencores.org/cores/aes_pipe/                     ----
----                                                              ----
---- Description                                                  ----
---- Implementation of AES IP core according to                   ----
---- FIPS PUB 197 specification document.                         ----
----                                                              ----
---- To Do:                                                       ----
----   -                                                          ----
----                                                              ----
---- Author:                                                      ----
----      - Subhasis Das, subhasis256@gmail.com                   ----
----                                                              ----
----------------------------------------------------------------------
----                                                              ----
---- Copyright (C) 2009 Authors and OPENCORES.ORG                 ----
----                                                              ----
---- This source file may be used and distributed without         ----
---- restriction provided that this copyright statement is not    ----
---- removed from the file and that any derivative work contains ----
---- the original copyright notice and the associated disclaimer. ----
----                                                              ----
---- This source file is free software; you can redistribute it   ----
---- and/or modify it under the terms of the GNU Lesser General   ----
---- Public License as published by the Free Software Foundation; ----
---- either version 2.1 of the License, or (at your option) any   ----
---- later version.                                               ----
----                                                              ----
---- This source is distributed in the hope that it will be       ----
---- useful, but WITHOUT ANY WARRANTY; without even the implied   ----
---- warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR      ----
---- PURPOSE. See the GNU Lesser General Public License for more ----
---- details.                                                     ----
----                                                              ----
---- You should have received a copy of the GNU Lesser General    ----
---- Public License along with this source; if not, download it   ----
---- from http://www.opencores.org/lgpl.shtml                     ----
----                                                              ----
----------------------------------------------------------------------
------------------------------------------------------
-- Project: AESFast
-- Author: Subhasis
-- Last Modified: 25/03/10
-- Email: subhasis256@gmail.com
------------------------------------------------------
--
-- Description: The Overall Core
-- Ports:
--			Clk: System Clock
--			plaintext_i: Input plaintext blocks
--			keyblock_i: Input keyblock
--			ciphertext_o: Output Cipher Block
------------------------------------------------------

library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.NUMERIC_STD.all;

library work;
use work.aes_pkg.all;

entity aes_top is
   port(
      Clk: in std_logic;
      RESET: in std_logic;
      start: in std_logic;
      ready: out std_logic;
      key_in: in std_logic_vector(127 downto 0);
      plaintext_in: in std_logic_vector(127 downto 0);
      ciphertext_out: out std_logic_vector(127 downto 0)
      );
end aes_top;

architecture rtl of aes_top is
   type state_type is (idle, aes_rounds);
   signal state_reg, state_next: state_type;

   signal ready_reg, ready_next: std_logic;

   signal key_reg, key_next: datablock;
   signal plaintext_reg, plaintext_next: datablock;

   signal nextkey: datablock;
   signal nextplain: datablock;

   signal rcon_in: std_logic_vector(7 downto 0);

   signal fc3_ir, c0_ir, c1_ir, c2_ir, c3_ir: blockcol; 
   signal fc3_lr, c0_lr, c1_lr, c2_lr, c3_lr: blockcol; 
   signal plain_ir1: datablock;
   signal SE_ir2: datablock;
   signal key_lr: datablock;

   signal key_in_conv: datablock;
   signal plaintext_in_conv: datablock;
   signal ciphertext_out_conv: datablock;

-- Large enough to count to 9 rounds.
   signal round_cnt_reg, round_cnt_next: unsigned(3 downto 0);

   begin

-- Convert from std_logic_vector to datablock. Note the required permutation for assignment to datablock. Reverse
-- happens for ciphertext_out below.
    key_conv_out: for I in 3 downto 0 generate
       key_conv_in: for J in 3 downto 0 generate
          key_in_conv(3-J, 3-I) <= key_in((I*32 + J*8 + 7) downto (I*32 + J*8));
       end generate;
    end generate;
    
    plaintext_conv_out: for I in 3 downto 0 generate
       plaintext_conv_in: for J in 3 downto 0 generate
           plaintext_in_conv(3-J, 3-I) <= plaintext_in((I*32 + J*8 + 7) downto (I*32 + J*8));
       end generate;
    end generate;

-- Combinational data path logic
-------------------------------------------------------
-- Coded as ((Addkey -> Sbox -> Mixcol) ... 9 times) -> Addkey -> Sbox -> Addkey (10 round)
-------------------------------------------------------

-- Note that ciphertext_out is NOT latched after the final round so we MUST hold the rcon_in(9) on inputs to add_f_1 below
-- after the last round to preserve ciphertext_out until the next 'start'.
   rcon_in <= rcon(to_integer(round_cnt_reg));

-- First 9 rounds, do this 
   add: entity work.addkey(rtl)
      port map (roundkey=>key_reg, datain=>plaintext_reg, rcon=>rcon_in, dataout=>plain_ir1, fc3=>fc3_ir, c0=>c0_ir, c1=>c1_ir, c2=>c2_ir, c3=>c3_ir);
   sbox: entity work.sboxshr(rtl)
      port map (blockin=>plain_ir1, fc3=>fc3_ir, c0=>c0_ir, c1=>c1_ir, c2=>c2_ir, c3=>c3_ir, nextkey=>nextkey, blockout=>SE_ir2);

   mix: entity work.colmix(rtl)
      port map (datain=>SE_ir2, dataout=>nextplain);

-- Always do this but not used until 10 round.
   add_f: entity work.addkey(rtl) 
      port map (roundkey=>nextkey, datain=>SE_ir2, rcon=>X"00", dataout=>ciphertext_out_conv);


-- =============================================================================================
-- State and register logic
-- =============================================================================================
      process(Clk, RESET)
         begin
         if ( RESET = '1' ) then
            state_reg <= idle;
            ready_reg <= '1';
            round_cnt_reg <= (others=>'0');
            key_reg <= zero_data;
            plaintext_reg <= zero_data;
         elsif ( Clk'event and Clk = '1' ) then
            state_reg <= state_next;
            ready_reg <= ready_next;
            round_cnt_reg <= round_cnt_next;
            key_reg <= key_next;
            plaintext_reg <= plaintext_next;
         end if; 
      end process;

-- =============================================================================================
-- Combo logic
-- =============================================================================================
   process (state_reg, start, ready_reg, key_reg, plaintext_reg, round_cnt_reg, nextkey, nextplain, key_in_conv, plaintext_in_conv)
      begin
      state_next <= state_reg;
      ready_next <= ready_reg;

      round_cnt_next <= round_cnt_reg;

      key_next <= key_reg;
      plaintext_next <= plaintext_reg;

      case state_reg is

-- =====================
         when idle =>
            ready_next <= '1';

            if ( start = '1' ) then
               ready_next <= '0';

-- Latch the inputs on start.
               key_next <= key_in_conv;
               plaintext_next <= plaintext_in_conv;

-- Initialize round cnter.
               round_cnt_next <= (others=>'0');
               state_next <= aes_rounds;
            end if;

-- =====================
-- Carry out 9 rounds. 10 round is done on return to idle
         when aes_rounds =>
            key_next <= nextkey;
            plaintext_next <= nextplain;

-- Keep round_cnt_reg at 9 after we finish and return to idle to preserve ciphertext_out -- see note above.
            round_cnt_next <= round_cnt_reg + 1;

            if ( round_cnt_reg = 8 ) then
               state_next <= idle;
            end if;
      end case;
   end process;

 -- Convert from datablock to std_logic_vector
   ciphertext_conv_out: for I in 3 downto 0 generate
      ciphertext_conv_in: for J in 3 downto 0 generate
         ciphertext_out((I*32 + J*8 + 7) downto (I*32 + J*8)) <= ciphertext_out_conv(3-J, 3-I);
      end generate;    end generate;

   ready <= ready_reg;

end rtl;
