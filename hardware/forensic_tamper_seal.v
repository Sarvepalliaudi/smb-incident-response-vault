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

module forensic_tamper_seal (
    input wire clk,
    input wire cold_reset_n,
    input wire seal_enable,
    input wire [63:0] evidence_digest_head_in,
    input wire write_attempt,
    output reg [63:0] evidence_digest_head,
    output reg locked,
    output reg tamper_violation
);

    always @(posedge clk or negedge cold_reset_n) begin
        if (!cold_reset_n) begin
            evidence_digest_head <= 64'b0;
            locked <= 1'b0;
            tamper_violation <= 1'b0;
        end else begin
            if (write_attempt && locked)
                tamper_violation <= 1'b1;

            if (seal_enable && !locked) begin
                evidence_digest_head <= evidence_digest_head_in;
                locked <= 1'b1;
            end
        end
    end

endmodule
