package com.exelens.backend.repository;

import com.exelens.backend.entity.AnalysisEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

/**
 * Spring Data JPA가 이 인터페이스를 보고 구현체를 자동으로 만들어준다.
 * JpaRepository<엔티티 타입, ID 타입>을 상속받는 것만으로
 * save(), findById(), findAll(), deleteById() 같은 기본 기능이 전부 생긴다.
 *
 * 메서드 이름을 규칙에 맞게 지으면("findAllByOrderBy...") Spring이 이름을 해석해서
 * 알아서 쿼리를 만들어준다 (쿼리를 직접 작성할 필요가 없다).
 */
public interface AnalysisRepository extends JpaRepository<AnalysisEntity, Long> {

    List<AnalysisEntity> findAllByOrderByCreatedAtDesc();
}
