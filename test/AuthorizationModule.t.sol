//SPDX-License-Identifier: MPL-2.0
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "CMTAT/modules/PauseModule.sol";
import "./HelperContract.sol";

contract AuthorizationModuleTest is
    Test,
    HelperContract,
    AuthorizationModule,
    PauseModule
{
    function setUp() public {
        vm.prank(OWNER);
        CMTAT_CONTRACT = new CMTAT(ZERO_ADDRESS);
        CMTAT_CONTRACT.initialize(
            OWNER,
            "CMTA Token",
            "CMTAT",
            "CMTAT_ISIN",
            "https://cmta.ch",
            IRuleEngine(ZERO_ADDRESS)
        );
    }

    // can grant role as the owner
    function testCanGrantRoleAsOwner() public {
        vm.prank(OWNER);
        vm.expectEmit(true, true, false, true);
        emit RoleGranted(PAUSER_ROLE, ADDRESS1, OWNER);

        CMTAT_CONTRACT.grantRole(PAUSER_ROLE, ADDRESS1);
        bool res1 = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertEq(res1, true);
    }

    // can revoke role as the owner
    function testRevokeRoleAsOwner() public {
        vm.prank(OWNER);
        CMTAT_CONTRACT.grantRole(PAUSER_ROLE, ADDRESS1);
        bool res1 = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertEq(res1, true);

        vm.prank(OWNER);
        vm.expectEmit(true, true, false, true);
        // emits a RoleRevoked event
        emit RoleRevoked(PAUSER_ROLE, ADDRESS1, OWNER);
        CMTAT_CONTRACT.revokeRole(PAUSER_ROLE, ADDRESS1);
        bool res2 = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertFalse(res2);
    }

    // reverts when granting from non-owner
    function testCannotGrantFromNonOwner() public {
        bool res1 = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertFalse(res1);

        string memory message = string(
            abi.encodePacked(
                "AccessControl: account ",
                vm.toString(ADDRESS2),
                " is missing role ",
                DEFAULT_ADMIN_ROLE_HASH
            )
        );
        vm.expectRevert(bytes(message));
        vm.prank(ADDRESS2);
        CMTAT_CONTRACT.grantRole(PAUSER_ROLE, ADDRESS1);

        bool res2 = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertFalse(res2);
    }

    // reverts when revoking from non-owner
    function testCannotRevokeFromNonOwner() public {
        bool res1 = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertFalse(res1);

        vm.prank(OWNER);
        CMTAT_CONTRACT.grantRole(PAUSER_ROLE, ADDRESS1);
        bool res2 = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertEq(res2, true);

        vm.prank(ADDRESS2);
        string memory message = string(
            abi.encodePacked(
                "AccessControl: account ",
                vm.toString(ADDRESS2),
                " is missing role ",
                DEFAULT_ADMIN_ROLE_HASH
            )
        );
        vm.expectRevert(bytes(message));
        CMTAT_CONTRACT.revokeRole(PAUSER_ROLE, ADDRESS1);

        bool res3 = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertEq(res3, true);
    }
}
