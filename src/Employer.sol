// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "sismo-connect-solidity/SismoLib.sol";
import "@openzeppelin/contracts/interfaces/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract Employer is SismoConnect, Ownable {
    using SismoConnectHelper for SismoConnectVerifiedResult;

    bytes16 public constant APP_ID = 0xd345943db0a9c43788a850b039560e05;

    mapping(address => Res) public verifiedEmployees;

    constructor() SismoConnect(APP_ID) { }

    struct Res {
        bytes16 appId;
        bytes16 namespace;
        bytes32 version;
        uint256 authLength;
        bytes signedMsg;
    }

    struct EmployeeProvision {
        address token;
        uint256 amount;
        address employee;
        uint256 start;
        uint256 expiry;
        mapping(address => bool) allowlist;
    }

    event AddVerifiedEmployee(address indexed employee, bytes16 indexed appId);
    event ProvisionEmployee(bytes32 indexed id, address indexed token, address indexed employee);
    event UpdateProvision(bytes32 indexed id);
    event SpendProvision(bytes32 indexed id, uint256 indexed amount, address indexed recipient);

    mapping(address => mapping(bytes32 => bool)) provisionIds;
    mapping(bytes32 => EmployeeProvision) provisions;

    mapping(address => string) public employeeRailgunAddr;

    modifier onlyVerifiedEmployee() {
        require(isVerifiedEmployee(msg.sender), "Not a verified employee");
        _;
    }

    function addVerifiedEmployee(bytes memory response) external {
        SismoConnectVerifiedResult memory result = verify({
            responseBytes: response,
            auth: buildAuth({authType: AuthType.VAULT}),
            signature: buildSignature({message: abi.encode(msg.sender)})
        });

        Res memory r = Res(result.appId, result.namespace, result.version, result.auths.length, result.signedMessage);
        verifiedEmployees[msg.sender] = r;

        emit AddVerifiedEmployee(msg.sender, result.appId);
    }

    function isVerifiedEmployee(address user) public view returns (bool) {
        return verifiedEmployees[user].appId == APP_ID;
    }

    function provisionEmployee(address _token, uint256 _amount, address _employee, uint256 _expiry, address[] calldata _allowlist) external onlyOwner {
        require(isVerifiedEmployee(_employee), "Can only provision to verified employee");
        
        IERC20(_token).transferFrom(msg.sender, address(this), _amount);

        bytes32 _provisionId = keccak256(abi.encodePacked(_token, _employee));

        provisionIds[_employee][_provisionId] = true;

        EmployeeProvision storage _employeeProvision = provisions[_provisionId];

        _employeeProvision.token = _token;
        _employeeProvision.amount = _amount;
        _employeeProvision.employee = _employee;
        _employeeProvision.start = block.timestamp;
        _employeeProvision.expiry = _expiry;

        for (uint256 i = 0; i < _allowlist.length; i++) {
            _employeeProvision.allowlist[_allowlist[i]] = true;
        }

        emit ProvisionEmployee(_provisionId, _token, _employee);
    }

    function updateProvision(bytes32 _provisionId, uint256 _amount, uint256 _expiry, address[] calldata _allowlist, address[] calldata _denylist) external onlyOwner {
        EmployeeProvision storage _employeeProvision = provisions[_provisionId];

        _employeeProvision.amount = _amount;
        _employeeProvision.expiry = _expiry;
        for (uint256 i = 0; i < _allowlist.length; i++) {
            _employeeProvision.allowlist[_allowlist[i]] = true;
        }

        for (uint256 i = 0; i < _denylist.length; i++) {
            _employeeProvision.allowlist[_denylist[i]] = false;
        }

        emit UpdateProvision(_provisionId);
    }

    function spendProvision(address _token, uint256 _amount, address _recipient) external onlyVerifiedEmployee {
        bytes32 _provisionId = keccak256(abi.encodePacked(_token, msg.sender));

        EmployeeProvision storage _employeeProvision = provisions[_provisionId];
        require(_employeeProvision.start + _employeeProvision.expiry > block.timestamp, "Provision expired");
        require(_employeeProvision.amount >= _amount, "Trying to spend more than provision");
        require(_employeeProvision.allowlist[_recipient] == true, "Recipient not on allowlist");
    
        IERC20(_token).transfer(_recipient, _amount);

        emit SpendProvision(_provisionId, _amount, _recipient);
    }

    function getProvisionId(address _user, address _token) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_user, _token));
    }

    function provideRailgunAddr(string calldata railgunAddr) external onlyVerifiedEmployee {
        employeeRailgunAddr[msg.sender] = railgunAddr;
    }
}

