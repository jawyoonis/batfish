﻿
$(document).ready(
    function () {
        fnGetWorkStatus();
    }
);

// -------------------------------------------------

function fnGetWorkStatus() {
    bfGetJson("GetWorkStatus", SVC_WORK_MGR_ROOT + SVC_WORK_GETSTATUS_RSC, cbGetWorkStatus);
}

function cbGetWorkStatus(result) {

    if (result[0] === SVC_SUCCESS_KEY) {
        var cWorks = result[1]["completed-works"];
        var iWorks = result[1]["incomplete-works"];

        jQuery("#txtCompletedWorks").val(cWorks);
        jQuery("#txtIncompleteWorks").val(iWorks);
    }
    else {
        UpdateDebugInfo("GetWorkStatusFailed: " + result[1]);
    }
}

// -------------------------------------------------

function fnAddWorker() {
    var worker = jQuery("#txtAddWorker").val();

    if (worker == "") {
        alert("Specify a worker first");
        return;
    }

    bfGetJson("AddWorker", SVC_POOL_MGR_ROOT + SVC_POOL_UPDATE_RSC + "?add=" + worker, cbAddWorker);
}

function cbAddWorker(result) {
    if (result[0] === SVC_SUCCESS_KEY) {
        UpdateDebugInfo("Worker added successfully");
    }
    else {
        UpdateDebugInfo("Worker addition failed: " + result[1]);
    }
}


function fnUploadTestrig() {

    var testrigName = jQuery("#txtTestrigName").val();

    if (testrigName == "") {
        alert("Specify a testrig name");
        return;
    }

    var testrigFile = jQuery("#fileUploadTestrig").get(0).files[0];

    if (typeof testrigFile === 'undefined') {
        alert("Select a testrig file");
        return;
    }

    var data = new FormData();
    data.append(SVC_TESTRIG_NAME_KEY, testrigName);
    data.append(SVC_ZIPFILE_KEY, testrigFile);

    bfUploadData("UploadTestrig " + testrigName, SVC_WORK_MGR_ROOT + SVC_WORK_UPLOAD_TESTRIG_RSC, data);
}

// -----------------------------------doWork-----------------------

var uuidCurrWork;
var currWorkChecker;

function fnDoWork(worktype) {

    uuidCurrWork = guid();

    //set the guid of the text field
    jQuery("#txtDoWorkGuid").val(uuidCurrWork);

    var testrigName = jQuery("#txtTestrigName").val();

    var reqParams = {};

    switch (worktype) {
        case "vendorspecific":
            reqParams[COMMAND_PARSE_VENDOR_SPECIFIC] = "";
            break;
        case "vendorindependent":
            reqParams[COMMAND_PARSE_VENDOR_INDEPENDENT] = "";
            break;
        case "generatefacts":
            reqParams[COMMAND_GENERATE_FACT] = "";
            reqParams[COMMAND_ENV] = jQuery("#txtEnvironmentName").val();
            break;
        case "generatedataplane":
            reqParams[COMMAND_COMPILE] = "";
            reqParams[COMMAND_FACTS] = "";
            reqParams[COMMAND_ENV] = jQuery("#txtEnvironmentName").val();
            break;
        case "getdataplane":
            reqParams[COMMAND_DUMP_DP] = "";
            reqParams[COMMAND_ENV] = jQuery("#txtEnvironmentName").val();
            break;
        case "getz3encoding":
            reqParams[COMMAND_SYNTHESIZE_Z3_DATA_PLANE] = "";
            reqParams[COMMAND_ENV] = jQuery("#txtEnvironmentName").val();
            break;
        case "answerquestion":
            reqParams[COMMAND_ANSWER] = "";
            reqParams[ARG_QUESTION_NAME] = jQuery("#txtQuestionName").val();
            break;
        case "postflows":
            reqParams[COMMAND_POST_FLOWS] = "";
            reqParams[ARG_QUESTION_NAME] = jQuery("#txtQuestionName").val();
            reqParams[COMMAND_ENV] = jQuery("#txtEnvironmentName").val();
            break;
        case "getflowtraces":
            reqParams[COMMAND_POST_FLOWS] = "";
            reqParams[ARG_PREDICATES] = PREDICATE_FLOW_PATH_HISTORY;
            reqParams[COMMAND_ENV] = jQuery("#txtEnvironmentName").val();
            break;
        default:
            UpdateDebugInfo("failed: unsupported work command", worktype);
    }

    var workItem = JSON.stringify([uuidCurrWork, testrigName, reqParams, {}]);

    //if we had an old work checker, kill it before queuing this work
    window.clearTimeout(currWorkChecker);

    new ServiceHelper().Get(SVC_WORK_MGR_ROOT + SVC_WORK_QUEUE_WORK_RSC + "?" + SVC_WORKITEM_KEY + "=" + workItem, cbDoWork);
}

function cbDoWork(context, result) {
    if (result[0] === SVC_SUCCESS_KEY) {
        UpdateDebugInfo("Work queued. Will continue checking.");
        currWorkChecker = window.setTimeout(fnCheckWork, 10 * 1000);
    }
    else {
        UpdateDebugInfo("Work queuing failed: " + result[1]);
    }
}

function fnCheckWork() {
    new ServiceHelper().Get(SVC_WORK_MGR_ROOT + SVC_WORK_GET_WORKSTATUS_RSC + "?" + SVC_WORKID_KEY + "=" + uuidCurrWork, cbCheckWork);
}

function cbCheckWork(context, result) {
    if (result[0] === SVC_SUCCESS_KEY) {
        UpdateDebugInfo(context, "Work checking succeeded");

        var status = result[1][SVC_WORKSTATUS_KEY];
        jQuery("#txtCheckWorkStatus").val(status);

        switch (status) {
            case "TERMINATEDNORMALLY":
            case "TERMINATEDABNORMALLY":
                break;
            case "UNASSIGNED":
            case "TRYINGTOASSIGN":
            case "ASSIGNED":
            case "ASSIGNMENTERROR":
            case "CHECKINGSTATUS":
                //fire again
                currWorkChecker = window.setTimeout(fnCheckWork, 10 * 1000);
                break;
            default:
                UpdateDebugInfo("Got unknown status: ", status);
        }        
    }
    else {
        UpdateDebugInfo("Work queuing failed: " + result[1]);
    }
}

function guid() {
    function s4() {
        return Math.floor((1 + Math.random()) * 0x10000)
          .toString(16)
          .substring(1);
    }
    return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
      s4() + '-' + s4() + s4() + s4();
}

function fnGetLog() {
    var testrigName = jQuery("#txtTestrigName").val();
    var uuidWork = jQuery("#txtDoWorkGuid").val();

    //sanity check what we got
    if (testrigName == "") {
        UpdateDebugInfo("Cannot fetch log. Testrig name is empty");
        return;
    }
    if (uuidWork == "") {
        UpdateDebugInfo("Cannot fetch log. Testrig name is empty");
        return;
    }

    helperGetObject(testrigName, uuidWork + ".log");
}

function fnGetObject(worktype) {

    var testrigName = jQuery("#txtTestrigName").val();

    if (testrigName == "") {
        UpdateDebugInfo("Cannot fetch result. Testrig name is empty");
        return;
    }

    var envName = jQuery("#txtEnvironmentName").val();
    if (envName == "" && worktype.substring(0, 6) == "vendor") { //vendor* worktype does not need an environment
        UpdateDebugInfo("Cannot fetch result for", worktype, "Environment name is empty");
        return;
    }

    var objectName = "unknown";

    switch (worktype) {
        case "vendorspecific":
            objectName = RELPATH_VENDOR_SPECIFIC_CONFIG_DIR;
            break;
        case "vendorindependent":
            objectName = RELPATH_VENDOR_INDEPENDENT_CONFIG_DIR;
            break;
        case "generatefacts":
            objectName = [RELPATH_ENVIRONMENTS_DIR, envName, RELPATH_FACT_DUMP_DIR].join("/");
            break;
        case "getdataplane":
            objectName = [RELPATH_ENVIRONMENTS_DIR, envName, RELPATH_DATA_PLANE_DIR].join("/");
            break;
        case "getz3encoding":
            objectName = [RELPATH_ENVIRONMENTS_DIR, envName, RELPATH_Z3_DATA_PLANE_FILE].join("/");
            break;
        case "getflowtraces":
            objectName = [RELPATH_ENVIRONMENTS_DIR, envName, RELPATH_QUERY_DUMP_DIR].join("/");
            break;
        default:
            UpdateDebugInfo("failed: unsupported worktype for get result", worktype);
    }

    helperGetObject(testrigName, objectName);
}

function helperGetObject(testrigName, objectName) {
    var uri = encodeURI(SVC_WORK_MGR_ROOT + SVC_WORK_GET_OBJECT_RSC + "?" + SVC_TESTRIG_NAME_KEY + "=" + testrigName + "&" + SVC_WORK_OBJECT_KEY + "=" + objectName);
    window.location.assign(uri);
}

function fnUploadEnvironment() {
    var data = new FormData();
    data.append(SVC_TESTRIG_NAME_KEY, jQuery("#txtTestrigName").val());
    data.append(SVC_ENV_NAME_KEY, jQuery("#txtEnvironmentName").val());
    data.append(SVC_ZIPFILE_KEY, jQuery("#fileUploadEnvironment").get(0).files[0]);

    jQuery.ajax({
        url: SVC_WORK_MGR_ROOT + SVC_WORK_UPLOAD_ENV_RSC,
        type: "POST",
        contentType: false,
        processData: false,
        data: data,

        error: function (_, textStatus, errorThrown) {
            UpdateDebugInfo("Environment upload failed:", textStatus, errorThrown);
            console.log(textStatus, errorThrown);
        },
        success: function (response, textStatus) {
            if (response[0] === SVC_SUCCESS_KEY) {
                UpdateDebugInfo("Environment uploaded");
            }
            else {
                UpdateDebugInfo("Environment upload failed: " + response[1]);
            }
        }
    });
}

function fnUploadQuestion() {
    var data = new FormData();
    data.append(SVC_TESTRIG_NAME_KEY, jQuery("#txtTestrigName").val());
    data.append(SVC_QUESTION_NAME_KEY, jQuery("#txtQuestionName").val());
    data.append(SVC_FILE_KEY, jQuery("#fileUploadQuestion").get(0).files[0]);

    jQuery.ajax({
        url: SVC_WORK_MGR_ROOT + SVC_WORK_UPLOAD_QUESTION_RSC,
        type: "POST",
        contentType: false,
        processData: false,
        data: data,

        error: function (_, textStatus, errorThrown) {
            UpdateDebugInfo("Question upload failed:", textStatus, errorThrown);
            console.log(textStatus, errorThrown);
        },
        success: function (response, textStatus) {
            if (response[0] === SVC_SUCCESS_KEY) {
                UpdateDebugInfo("Question uploaded");
            }
            else {
                UpdateDebugInfo("Question upload failed: " + response[1]);
            }
        }
    });
}


//function UpdateDebugInfo(object, string) {
//    if ($("#divDebugInfo").is(':hidden'))
//          return;
//    $("#divDebugInfo").html(string);
//}

var debugLog = [];
var maxLogEntries = 10;

function UpdateDebugInfo(string) {

    debugLog.push(bfGetTimestamp() + " " + string);

    while (debugLog.length > maxLogEntries) {
        debugLog.shift();
    }

    $("#divDebugInfo").html(debugLog.join("<br/>"));
}

function bfGetTimestamp() {
    var now = new Date();
    var time = [now.getHours(), now.getMinutes(), now.getSeconds()];
    return time.join(":");
}