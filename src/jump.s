.text
.global _start

@addr1
.org 0x2714			@origin of the first address. this can be the jump start or destination ,but should be lower then the next org.
_start:
    B     jump_here	@label to branch from

@addr2
.org 0x11c394		@origin of the second address. this can be the jump destination, or start ,but should be higher then the previous org.
jump_here:			@label to branch to
.end
