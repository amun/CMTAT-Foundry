//SPDX-License-Identifier: MPL-2.0
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "CMTAT/modules/EnforcementModule.sol";
import "CMTAT/modules/PauseModule.sol";
import "CMTAT/modules/AuthorizationModule.sol";
import "./HelperContract.sol";

contract EnforcementAuthorizationModule is
    Test,
    HelperContract,
    EnforcementModule,
    PauseModule,
    AuthorizationModule
{
    bool resBool;

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
        vm.expectEmit(true, true, true, false);
        emit RoleGranted(PAUSER_ROLE, ADDRESS1, OWNER);
        vm.prank(OWNER);
        CMTAT_CONTRACT.grantRole(PAUSER_ROLE, ADDRESS1);
        resBool = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertEq(resBool, true);
    }

    // can revoke role as the owner
    function testRevokeRoleAsOwner() public {
        vm.prank(OWNER);
        CMTAT_CONTRACT.grantRole(PAUSER_ROLE, ADDRESS1);
        resBool = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertEq(resBool, true);
        vm.prank(OWNER);
        vm.expectEmit(true, true, true, false);
        emit RoleRevoked(PAUSER_ROLE, ADDRESS1, OWNER);
        CMTAT_CONTRACT.revokeRole(PAUSER_ROLE, ADDRESS1);
        resBool = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertFalse(resBool);
    }

    // reverts when granting from non-owner
    function testCannotGrantRoleByNonOwner() public {
        resBool = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertFalse(resBool);
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
        CMTAT_CONTRACT.grantRole(PAUSER_ROLE, ADDRESS1);
        resBool = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertFalse(resBool);
    }

    // reverts when revoking from non-owner
    function testCannotRevokeRoleByNonOwner() public {
        resBool = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertFalse(resBool);
        vm.prank(OWNER);
        CMTAT_CONTRACT.grantRole(PAUSER_ROLE, ADDRESS1);
        resBool = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertEq(resBool, true);
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
        resBool = CMTAT_CONTRACT.hasRole(PAUSER_ROLE, ADDRESS1);
        assertEq(resBool, true);
    }
}
