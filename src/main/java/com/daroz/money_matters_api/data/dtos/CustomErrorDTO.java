package com.daroz.money_matters_api.data.dtos;

import java.time.Instant;

public record CustomErrorDTO (
        Instant timestamp,
        Integer status,
        String error,
        String path
){
}
