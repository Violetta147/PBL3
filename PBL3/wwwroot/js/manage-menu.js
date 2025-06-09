// wwwroot/js/manage-menu.js
$(document).ready(function () {
    var bootstrapModalInstance = null; // Sẽ được khởi tạo một lần
    var $modalElement = $('#menuCrudModal');
    var $modalBody = $('#menuCrudModalBody');
    var $modalTitle = $('#menuCrudModalLabel');
    var $lastFocusedElementBeforeModal;
    var antiForgeryToken = $('form input[name="__RequestVerificationToken"]').first().val() || $('meta[name="x-csrf-token"]').attr('content');

    if (!antiForgeryToken) {
        console.warn("Anti-forgery token not found. AJAX POST/DELETE requests might fail or be insecure.");
    }

    // Khởi tạo Bootstrap Modal instance một lần
    if ($modalElement.length) {
        bootstrapModalInstance = new bootstrap.Modal($modalElement[0], {
            backdrop: 'static', // Ngăn đóng khi click ra ngoài
            keyboard: false     // Ngăn đóng bằng phím Esc (có thể đặt true nếu muốn)
        });
    } else {
        console.error("Modal element with ID 'menuCrudModal' not found.");
        return; // Không thể tiếp tục nếu không có modal
    }

    function showModalLoading() {
        $modalBody.html('<div class="text-center p-5"><div class="spinner-border text-primary" style="width: 3rem; height: 3rem;" role="status"><span class="visually-hidden">Loading...</span></div><p class="mt-2">Đang tải...</p></div>');
    }

    function showModalError(message, isHtml = false) {
        var content = isHtml ? message : escapeHtml(message || "Đã có lỗi xảy ra. Vui lòng thử lại.");
        var errorMessageHtml =
            '<div class="alert alert-danger m-0 p-3">' + content + '</div>' + // Thêm padding
            '<div class="modal-footer border-top-0 pt-3">' +
            '<button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Đóng</button>' +
            '</div>';
        $modalBody.html(errorMessageHtml);
    }

    function reparseFormValidation($form) {
        if ($form && $form.length && typeof $.validator !== 'undefined' && typeof $.validator.unobtrusive !== 'undefined') {
            $form.removeData('validator').removeData('unobtrusiveValidation');
            $.validator.unobtrusive.parse($form);
        }
    }

    function escapeHtml(unsafe) {
        if (typeof unsafe !== 'string') return '';
        return unsafe
            .replace(/&/g, "&")
            .replace(/</g, "<")
            .replace(/>/g, ">")
            .replace(/"/g, "\"")
                .replace(/'/g, "'");
    }

    $modalElement.on('show.bs.modal', function () {
        $lastFocusedElementBeforeModal = $(document.activeElement);
    });

    $modalElement.on('hidden.bs.modal', function () {
        if ($lastFocusedElementBeforeModal && $lastFocusedElementBeforeModal.length && document.body.contains($lastFocusedElementBeforeModal[0])) {
            $lastFocusedElementBeforeModal.trigger('focus');
        } else {
            var $mainCreateButton = $('button[data-url*="GetCreateMenuForm"]').first();
            if ($mainCreateButton.length) {
                $mainCreateButton.trigger('focus');
            }
        }
        $modalBody.html(''); // Dọn dẹp nội dung modal
        $modalTitle.text("Quản lý"); // Reset tiêu đề
    });

    $('body').on('click', 'button[data-bs-toggle="modal"][data-bs-target="#menuCrudModal"]', function (event) {
        event.preventDefault();
        var $button = $(this);
        var url = $button.data('url');
        var title = $button.data('modal-title');

        if (!url) {
            console.error("Button does not have a data-url attribute.");
            showModalError("Lỗi cấu hình: Nút không có đường dẫn dữ liệu.");
            if (bootstrapModalInstance) bootstrapModalInstance.show();
            return;
        }

        $modalTitle.text(title || "Quản lý");
        showModalLoading();
        if (bootstrapModalInstance) bootstrapModalInstance.show();

        $.get(url)
            .done(function (response) {
                $modalBody.html(response);
                var $form = $modalBody.find("form");
                reparseFormValidation($form);
            })
            .fail(function (jqXHR, textStatus, errorThrown) {
                console.error("Error loading modal content: ", textStatus, errorThrown, jqXHR.responseText);
                var errorMsg = jqXHR.status === 0 ? 'Lỗi mạng hoặc không thể kết nối server.' :
                    jqXHR.status === 401 ? 'Phiên làm việc hết hạn hoặc không có quyền.' :
                        jqXHR.status === 403 ? 'Bạn không có quyền thực hiện hành động này.' :
                            jqXHR.status === 404 ? 'Không tìm thấy tài nguyên yêu cầu (' + url + ').' :
                                'Lỗi tải nội dung form. Vui lòng thử lại.';
                if (jqXHR.responseText && jqXHR.responseText.length < 500 && jqXHR.responseText.indexOf('<html') === -1) {
                    errorMsg += '<br><small>' + escapeHtml(jqXHR.responseText) + '</small>';
                }
                showModalError(errorMsg, true);
            });
    });

    window.handleMenuFormSuccess = function (data, status, xhr) {
        if (data.success) {
            if (bootstrapModalInstance) {
                bootstrapModalInstance.hide();
            }
            showGlobalSuccessMessage(data.message || "Thao tác thành công!");
            refreshMenuStructure();
        } else {
            var errorMessage = data.message || "Dữ liệu không hợp lệ. Vui lòng kiểm tra lại.";
            var errorDetails = "";
            if (data.errors && typeof data.errors === 'object') {
                errorDetails = '<ul class="list-unstyled mb-0 text-start">';
                $.each(data.errors, function (key, values) {
                    var fieldDisplayName = key; // Cần một cách để lấy DisplayName của trường nếu có
                    $.each(values, function (index, value) {
                        errorDetails += "<li>" + (fieldDisplayName ? escapeHtml(fieldDisplayName) + ": " : "") + escapeHtml(value) + "</li>";
                    });
                });
                errorDetails += "</ul>";
                errorMessage = data.message ? escapeHtml(data.message) + "<hr class='my-2'/>" + errorDetails : errorDetails;
            } else if (data.message) {
                errorMessage = escapeHtml(data.message);
            }

            var $formInModal = $modalBody.find('form');
            var $summaryDiv = $formInModal.find('div[data-valmsg-summary="true"]');
            if ($summaryDiv.length === 0 && $formInModal.length > 0) {
                $formInModal.prepend('<div class="alert alert-danger validation-summary-errors mt-0 mb-3" data-valmsg-summary="true" role="alert"></div>');
                $summaryDiv = $formInModal.find('.validation-summary-errors').first();
            }
            $summaryDiv.html(errorMessage).show(); // errorMessage có thể chứa HTML
            // Không reparse ở đây, vì đây là lỗi từ server
        }
    };
    window.handleSectionFormSuccess = window.handleMenuFormSuccess;
    window.handleItemFormSuccess = window.handleMenuFormSuccess;

    window.handleMenuFormFailure = function (xhr, status, error) {
        console.error("AJAX submission server error: ", status, error, xhr.status, xhr.responseText);
        var errorMessage = "Lỗi máy chủ (" + xhr.status + "): ";
        try {
            var responseJson = JSON.parse(xhr.responseText);
            if (responseJson) {
                if (responseJson.title) errorMessage += escapeHtml(responseJson.title);
                else if (responseJson.message) errorMessage += escapeHtml(responseJson.message);

                if (responseJson.errors && typeof responseJson.errors === 'object') {
                    errorMessage += "<ul class='list-unstyled mt-2 text-start'>";
                    $.each(responseJson.errors, function (key, values) {
                        $.each(values, function (index, value) {
                            errorMessage += "<li>" + escapeHtml(value) + "</li>";
                        });
                    });
                    errorMessage += "</ul>";
                }
            } else if (xhr.responseText && xhr.responseText.length < 1000 && xhr.responseText.indexOf('<html') === -1) {
                errorMessage += escapeHtml(xhr.responseText);
            } else {
                errorMessage += "Không thể xử lý yêu cầu. Vui lòng thử lại sau.";
            }
        } catch (e) {
            if (xhr.responseText && xhr.responseText.length < 1000 && xhr.responseText.indexOf('<html') === -1) {
                errorMessage += escapeHtml(xhr.responseText);
            } else {
                errorMessage += "Không thể xử lý yêu cầu hoặc phản hồi không đúng định dạng. Vui lòng thử lại sau.";
            }
        }
        var $formInModal = $modalBody.find('form');
        var $summaryDiv = $formInModal.find('div[data-valmsg-summary="true"]');
        if ($summaryDiv.length === 0 && $formInModal.length > 0) {
            $formInModal.prepend('<div class="alert alert-danger validation-summary-errors mt-0 mb-3" data-valmsg-summary="true" role="alert"></div>');
            $summaryDiv = $formInModal.find('.validation-summary-errors').first();
        }
        $summaryDiv.html(errorMessage).show(); // errorMessage có thể chứa HTML
    };
    window.handleSectionFormFailure = window.handleMenuFormFailure;
    window.handleItemFormFailure = window.handleMenuFormFailure;

    $('#menuStructureContainer').on('click', '.btn-delete-menu, .btn-delete-section, .btn-delete-item', function (event) {
        event.preventDefault();
        var $button = $(this);
        var id = $button.data('id');
        var name = $button.data('name') || "mục này";
        var typeText = "đối tượng";
        var deleteUrl = $button.data('url');

        if ($button.hasClass('btn-delete-menu')) { typeText = "Thực đơn"; }
        else if ($button.hasClass('btn-delete-section')) { typeText = "Mục"; }
        else if ($button.hasClass('btn-delete-item')) { typeText = "Món ăn"; }

        if (!deleteUrl || typeof id === 'undefined') {
            showGlobalErrorMessage("Lỗi cấu hình nút xóa.");
            return;
        }

        var originalButtonHtml = $button.html();
        $button.data('original-html', originalButtonHtml);

        Swal.fire({
            title: 'Xác nhận xóa',
            html: `Bạn có chắc chắn muốn xóa <strong>${typeText} "${escapeHtml(name)}"</strong> không?<br/>Hành động này không thể hoàn tác.`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#6c757d',
            confirmButtonText: 'Xóa!',
            cancelButtonText: 'Hủy bỏ',
            customClass: {
                confirmButton: 'btn btn-danger ms-2',
                cancelButton: 'btn btn-secondary'
            },
            buttonsStyling: false // Để sử dụng class Bootstrap
        }).then((result) => {
            if (result.isConfirmed) {
                if (!antiForgeryToken) {
                    showGlobalErrorMessage("Lỗi bảo mật. Vui lòng làm mới trang.");
                    return;
                }
                $.ajax({
                    url: deleteUrl,
                    type: 'POST',
                    data: {
                        __RequestVerificationToken: antiForgeryToken,
                        id: id
                    },
                    beforeSend: function () {
                        $button.prop('disabled', true).html('<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Đang xóa...');
                    },
                    success: function (response) {
                        if (response.success) {
                            showGlobalSuccessMessage(response.message || `${typeText} đã được xóa thành công.`);
                            refreshMenuStructure();
                        } else {
                            showGlobalErrorMessage("Lỗi khi xóa: " + (response.message || "Không thể xóa."));
                        }
                    },
                    error: function (xhr) {
                        console.error("Error deleting: ", xhr.status, xhr.responseText);
                        showGlobalErrorMessage("Đã có lỗi máy chủ khi xóa. Chi tiết: " + (xhr.responseText || "Unknown error"));
                    },
                    complete: function () {
                        $button.prop('disabled', false).html($button.data('original-html'));
                    }
                });
            }
        });
    });

    function refreshMenuStructure() {
        var $container = $("#menuStructureContainer");
        var restaurantId = $container.data('restaurant-id'); // Đọc từ data attribute

        if (!restaurantId || parseInt(restaurantId, 10) <= 0) {
            console.error("Restaurant ID không hợp lệ hoặc không được tìm thấy từ data-restaurant-id trên #menuStructureContainer.");
            $container.html('<div class="alert alert-danger">Lỗi: Không thể xác định nhà hàng để tải lại thực đơn. Vui lòng đảm bảo data-restaurant-id được thiết lập đúng trên thẻ div#menuStructureContainer.</div>');
            return;
        }

        $container.html('<div class="text-center p-5"><div class="spinner-border text-primary" style="width: 3rem; height: 3rem;" role="status"><span class="visually-hidden">Đang tải lại...</span></div><p class="mt-2">Đang làm mới thực đơn...</p></div>');
        var refreshUrl = `/Business/GetMenuStructurePartial?restaurantId=${encodeURIComponent(restaurantId)}`;

        $.get(refreshUrl)
            .done(function (response) {
                $container.html(response);
            })
            .fail(function (jqXHR) {
                console.error("Không thể làm mới cấu trúc menu:", jqXHR.status, jqXHR.responseText);
                $container.html('<div class="alert alert-danger">Không thể tải lại cấu trúc thực đơn. Chi tiết: ' + (jqXHR.responseText || 'Lỗi không xác định') + '</div>');
            });
    }

    function showGlobalMessage(message, type = 'info') {
        if ($('#global-alert-container').length === 0) {
            var $mainContentArea = $('.dashboard-container main').first();
            if ($mainContentArea.length === 0) $mainContentArea = $('.container').first(); // Fallback
            $mainContentArea.prepend('<div id="global-alert-container" class="mb-3" style="position: sticky; top: 1rem; z-index: 1060;"></div>');
        }
        var alertId = type + '-alert-' + Date.now();
        var alertClass = 'alert-' + type;
        var iconClass = type === 'success' ? 'fa-check-circle' :
            type === 'error' ? 'fa-times-circle' :
                type === 'warning' ? 'fa-exclamation-triangle' : 'fa-info-circle';

        $('#global-alert-container').append(
            '<div class="alert ' + alertClass + ' alert-dismissible fade show" role="alert" id="' + alertId + '">' +
            '<i class="fas ' + iconClass + ' me-2"></i>' +
            escapeHtml(message) +
            '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>' +
            '</div>'
        );
        if (type === 'success' || type === 'info') {
            setTimeout(function () {
                $('#' + alertId).alert('close');
            }, 5000);
        }
    }
    window.showGlobalSuccessMessage = function (message) { showGlobalMessage(message, 'success'); }
    window.showGlobalErrorMessage = function (message) { showGlobalMessage(message, 'error'); }

});