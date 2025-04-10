package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"server/global"
	"server/model/request"
	"server/model/response"
)

type ImageApi struct{}

func (i *ImageApi) ImageUpload(c *gin.Context) {
	_, header, err := c.Request.FormFile("image")
	if err != nil {
		global.Log.Error(err.Error(), zap.Error(err))
		response.FailWithMessage(err.Error(), c)
		return
	}

	url, err := imageService.ImageUpload(header)
	if err != nil {
		global.Log.Error("Failed to upload image:", zap.Error(err))
		response.FailWithMessage("Failed to upload image", c)
		return
	}
	response.OkWithDetailed(response.ImageUpload{
		Url:     url,
		OssType: global.Config.System.OssType,
	}, "Successfully uploaded image", c)
}

func (i *ImageApi) ImageDelete(c *gin.Context) {
	var req request.ImageDelete
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	err = imageService.ImageDelete(req)
	if err != nil {
		global.Log.Error("Failed to delete image:", zap.Error(err))
		response.FailWithMessage("Failed to delete image", c)
		return
	}
	response.OkWithMessage("Successfully deleted image", c)
}

func (i *ImageApi) ImageList(c *gin.Context) {
	var pageInfo request.ImageList
	err := c.ShouldBindQuery(&pageInfo)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	images, total, err := imageService.ImageList(pageInfo)
	if err != nil {
		global.Log.Error("Failed to list images:", zap.Error(err))
		response.FailWithMessage("Failed to list images", c)
		return
	}
	response.OkWithDetailed(response.PageResult{
		List:  images,
		Total: total,
	}, "Successfully listed images", c)
}
