/*
 * smb-ir-vault — Small Business 6-Phase Incident Response Plan & SHA3-512 Forensic Evidence Locker
 * Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan.
 * This specification and dual hardware-software architecture is original work created solely for this application.
 * B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester),
 * Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India.
 * Cybersecurity Virtual Internship — Dev/Craft by Fennark: https://devcraft.fennark.xyz
 * Intern ID DEV-CRAFT-BQ2VPH, Task 7: Incident Response Plan.
 * LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/
 * GitHub: https://github.com/Sarvepalliaudi
 */

`timescale 1ns/1ps

module tb_forensic_tamper_seal;
    reg clk = 1'b0;
    reg cold_reset_n = 1'b0;
    reg seal_enable = 1'b0;
    reg [63:0] evidence_digest_head_in = 64'b0;
    reg write_attempt = 1'b0;
    wire [63:0] evidence_digest_head;
    wire locked;
    wire tamper_violation;

    forensic_tamper_seal dut (
        .clk(clk),
        .cold_reset_n(cold_reset_n),
        .seal_enable(seal_enable),
        .evidence_digest_head_in(evidence_digest_head_in),
        .write_attempt(write_attempt),
        .evidence_digest_head(evidence_digest_head),
        .locked(locked),
        .tamper_violation(tamper_violation)
    );

    always #5 clk = ~clk;

    initial begin
        #1;
        cold_reset_n = 1'b1;
        #1;
        cold_reset_n = 1'b0;
        #1;
        if (locked !== 1'b0 || tamper_violation !== 1'b0)
            $fatal(1, "cold reset did not clear the seal state");

        cold_reset_n = 1'b1;
        evidence_digest_head_in = 64'h0123456789abcdef;
        seal_enable = 1'b1;
        @(posedge clk);
        #1;
        seal_enable = 1'b0;
        if (locked !== 1'b1 || evidence_digest_head !== 64'h0123456789abcdef)
            $fatal(1, "seal did not latch the digest head");

        evidence_digest_head_in = 64'hfedcba9876543210;
        write_attempt = 1'b1;
        @(posedge clk);
        #1;
        write_attempt = 1'b0;
        if (tamper_violation !== 1'b1)
            $fatal(1, "write attempt while locked did not raise tamper_violation");
        if (evidence_digest_head !== 64'h0123456789abcdef || locked !== 1'b1)
            $fatal(1, "locked digest head changed after a write attempt");

        cold_reset_n = 1'b0;
        #1;
        if (locked !== 1'b0 || tamper_violation !== 1'b0 || evidence_digest_head !== 64'b0)
            $fatal(1, "cold reset did not clear the seal");

        $display("[PASS] write-once forensic tamper seal self-checks passed");
        $finish;
    end
endmodule
